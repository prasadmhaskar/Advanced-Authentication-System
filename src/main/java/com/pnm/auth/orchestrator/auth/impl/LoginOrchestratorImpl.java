package com.pnm.auth.orchestrator.auth.impl;

import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.dto.request.LoginRequest;
import com.pnm.auth.dto.response.UserResponse;
import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.dto.result.MfaResult;
import com.pnm.auth.dto.result.RiskResult;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.event.FailureEvent;
import com.pnm.auth.event.SuccessEvent;
import com.pnm.auth.exception.custom.HighRiskLoginException;
import com.pnm.auth.orchestrator.auth.interfaces.LoginOrchestrator;
import com.pnm.auth.service.interfaces.auth.MfaService;
import com.pnm.auth.service.interfaces.auth.PasswordAuthService;
import com.pnm.auth.service.interfaces.auth.TokenService;
import com.pnm.auth.service.interfaces.auth.UserValidationService;
import com.pnm.auth.service.interfaces.device.DeviceTrustService;
import com.pnm.auth.service.interfaces.email.EmailService;
import com.pnm.auth.service.interfaces.risk.RiskEngineService;
import com.pnm.auth.util.MaskingUtil;
import com.pnm.auth.util.UserAgentParser;
import com.pnm.auth.web.context.RequestContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.Set;

@Service
@RequiredArgsConstructor
@Slf4j
public class LoginOrchestratorImpl implements LoginOrchestrator {

    private final UserValidationService userValidationService;
    private final PasswordAuthService passwordAuthService;
    private final RiskEngineService riskEngineService;
    private final MfaService mfaService;
    private final TokenService tokenService;
    private final DeviceTrustService deviceTrustService;
    private final ApplicationEventPublisher eventPublisher;
    private final EmailService emailService;

    @Value("${auth.risk.threshold.high}")
    private int highRiskScore;

    @Value("${auth.risk.threshold.medium}")
    private int mediumRiskScore;

    // Hardcoded whitelist for demo accounts to prevent Risk Blocking during testing
    private static final Set<String> DEMO_ACCOUNTS = Set.of("admin@demo.com", "user@demo.com");

    @Override
    public AuthenticationResult login(LoginRequest request, RequestContext ctx) {

        String ip = ctx.ip();
        String userAgent = ctx.userAgent();
        String email = request.getEmail().trim().toLowerCase();

        log.info("LoginOrchestrator: started for email={}", MaskingUtil.maskEmail(email));

        // Load user
        User user = userValidationService.findUserByEmail(email).orElse(null);

        String message = user == null ? "Non-registered user trying to login" : "Invalid password entered";

        // Password verification
        try {
            passwordAuthService.verifyPassword(user, request.getPassword());
        } catch (RuntimeException ex) {
            eventPublisher.publishEvent(new FailureEvent(user == null ? null : user.getId(), email, ip, userAgent, message));
            throw ex;
        }

        // User status check - Active/Blocked
        try {
            userValidationService.validateUserStatus(user);
        } catch (RuntimeException ex) {
            eventPublisher.publishEvent(new FailureEvent(user == null ? null : user.getId(), email, ip, userAgent, "Blocked / Non-verified user trying to login"));
            throw ex;
        }

        if (user == null) {
            throw new IllegalStateException("User is null after password verification.");
        }

        // Mfa handling
        if (user.isMfaEnabled()) {
            log.info("LoginOrchestrator: MFA enabled for email={}", MaskingUtil.maskEmail(user.getEmail()));
            MfaResult mfaResult = mfaService.handleMfaLogin(user);

            return AuthenticationResult.builder()
                    .outcome(AuthOutcome.MFA_REQUIRED)
                    .otpTokenId(mfaResult.getTokenId())
                    .message("OTP has been dispatched to your email address.")
                    .build();
        }

        RiskResult risk;
        if (DEMO_ACCOUNTS.contains(email)) {
            log.info("LoginOrchestrator: Skipping Risk Engine for DEMO account: {}", email);
            // Force 0 risk score so they never get blocked or asked for OTP
            risk = RiskResult.builder()
                    .score(0)
                    .blocked(false)
                    .otpRequired(false)
                    .build();
        } else {
            // Risk engine - only for non-mfa users
            risk = riskEngineService.evaluateRisk(user.getId(), ip, userAgent);
        }
            if (risk.getScore() >= highRiskScore) {
                log.warn("LoginOrchestrator: HIGH RISK → login blocked for ip={} and security email sent to email={}", ip, MaskingUtil.maskEmail(user.getEmail()));
                emailService.sendHighRiskAlert(user.getEmail(), ip, userAgent, risk.getReasons());
                eventPublisher.publishEvent(new FailureEvent(user.getId(), user.getEmail(), ip, userAgent, "High risk Email login"));
                throw new HighRiskLoginException("Login blocked due to high risk activity.");
            }

            if (risk.getScore() >= mediumRiskScore) {
                log.warn("LoginOrchestrator: MEDIUM RISK → OTP required email={}", MaskingUtil.maskEmail(email));
                MfaResult mfaResult = mfaService.handleMediumRiskOtp(user);

                return AuthenticationResult.builder()
                        .outcome(mfaResult.getOutcome())
                        .otpTokenId(mfaResult.getTokenId())
                        .message("Suspicious login detected, verification required. OTP has been sent to your email address.")
                        .build();
            }

        // Successful login: generate tokens
        AuthenticationResult result = tokenService.generateTokens(user, ctx);

        eventPublisher.publishEvent(new SuccessEvent(user.getId(), user.getEmail(), ip, userAgent, "Email login successful"));

        try {
            var agent = UserAgentParser.parse(userAgent);
            deviceTrustService.trustDevice(user.getId(), agent.getSignature(), agent.getDeviceName());
        } catch (Exception ex) {
            log.warn("LoginOrchestrator: failed to trust device", ex);
        }

        log.info("LoginOrchestrator: finished for email={}", MaskingUtil.maskEmail(email));

        return AuthenticationResult.builder()
                .outcome(AuthOutcome.SUCCESS)
                .accessToken(result.getAccessToken())
                .refreshToken(result.getRefreshToken())
                .message("Login successful")
                .user(UserResponse.from(user))
                .build();
    }
}
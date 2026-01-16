package com.pnm.auth.orchestrator.auth.impl;

import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.dto.request.LoginRequest;
import com.pnm.auth.dto.response.UserResponse;
import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.dto.result.MfaResult;
import com.pnm.auth.dto.result.RiskResult;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.event.LoginSuccessEvent;
import com.pnm.auth.exception.custom.HighRiskLoginException;
import com.pnm.auth.orchestrator.auth.LoginOrchestrator;
import com.pnm.auth.service.auth.MfaService;
import com.pnm.auth.service.auth.PasswordAuthService;
import com.pnm.auth.service.auth.TokenService;
import com.pnm.auth.service.auth.UserValidationService;
import com.pnm.auth.service.device.DeviceTrustService;
import com.pnm.auth.service.email.EmailService;
import com.pnm.auth.service.login.LoginActivityService;
import com.pnm.auth.service.risk.RiskEngineService;
import com.pnm.auth.util.MaskingUtil;
import com.pnm.auth.util.UserAgentParser;
import com.pnm.auth.web.context.RequestContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import java.util.Optional;

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
    private final LoginActivityService loginActivityService;
    private final EmailService emailService;

    @Value("${auth.risk.threshold.high}")
    private int highRiskScore;

    @Value("${auth.risk.threshold.medium}")
    private int mediumRiskScore;

    @Override
    public AuthenticationResult login(LoginRequest request, RequestContext ctx) {

        String ip = ctx.ip();
        String userAgent = ctx.userAgent();
        String email = request.getEmail().trim().toLowerCase();

        log.info("LoginOrchestrator: started for email={}", MaskingUtil.maskEmail(email));

        // Load user
        Optional<User> userOpt = userValidationService.findUserByEmail(email);
        User user = userOpt.orElse(null);

        // Password verification
        try {
            passwordAuthService.verifyPassword(user, request.getPassword());
        } catch (RuntimeException ex) {
            loginActivityService.recordFailure(email, "Invalid email or password", ip, userAgent);
            throw ex;
        }

        // User status check - Active/Blocked
        try {
            userValidationService.validateUserStatus(user);
        } catch (RuntimeException ex) {
            loginActivityService.recordFailure(email, ex.getMessage(), ip, userAgent);
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

        // 5. Risk engine - only for non-Mfa users
        RiskResult risk = riskEngineService.evaluateRisk(user, ip, userAgent);

        if (risk.getScore() >= highRiskScore) {
            log.warn("LoginOrchestrator: HIGH RISK → login blocked for ip={} and security email sent to email={}",ip, MaskingUtil.maskEmail(user.getEmail()));
            emailService.sendHighRiskAlert(user, ip, userAgent, risk.getReasons());
            loginActivityService.recordFailure(user.getEmail(), "High risk email login", ip, userAgent);
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

        eventPublisher.publishEvent(new LoginSuccessEvent(user.getId(), user.getEmail(), ip, userAgent));

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
package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.domain.enums.AuthProviderType;
import com.pnm.auth.domain.enums.NextAction;
import com.pnm.auth.dto.request.LoginRequest;
import com.pnm.auth.dto.response.UserResponse;
import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.dto.result.MfaResult;
import com.pnm.auth.dto.result.RiskResult;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.event.LoginSuccessEvent;
import com.pnm.auth.exception.custom.*;
import com.pnm.auth.security.oauth.AccountLinkTokenService;
import com.pnm.auth.service.auth.MfaService;
import com.pnm.auth.service.auth.PasswordAuthService;
import com.pnm.auth.service.auth.TokenService;
import com.pnm.auth.service.auth.UserValidationService;
import com.pnm.auth.service.device.DeviceTrustService;
import com.pnm.auth.service.login.LoginActivityService;
import com.pnm.auth.service.risk.RiskEngineService;
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
    private final AccountLinkTokenService accountLinkTokenService;
    private final LoginActivityService loginActivityService;

    @Value("${auth.risk.threshold.high}")
    private int highRiskScore;

    @Value("${auth.risk.threshold.medium}")
    private int mediumRiskScore;

    @Override
    public AuthenticationResult login(LoginRequest request, RequestContext ctx) {

        String ip = ctx.ip();
        String userAgent = ctx.userAgent();

        String email = request.getEmail().trim().toLowerCase();

        log.info("LoginOrchestrator: started ip={} and email={}", ip, email);

        // load user we do not throw exceptions here if user is null.
        Optional<User> userOpt = userValidationService.findUserByEmail(email);
        User user = userOpt.orElse(null);


        // Case: user is not null and password is also not null. Means user has an account with email login.
        boolean isPasswordSet = (user != null && user.getPassword() != null);

        // Here we are handling both cases
        // 1. If user is null (attacker might check if user has an account or not), we will verify the password with fake hash for saving db call and returning fake response.
        // 2. User has an account we will check password with real password.
        if (user == null || isPasswordSet) {
            try {
                // If a user is null, this runs a fake hash (Timing Attack Protection)
                // If user has password, this verifies it.
                passwordAuthService.verifyPassword(user, request.getPassword());
            } catch (InvalidCredentialsException ex) {
                loginActivityService.recordFailure(email, "Invalid email or password", ip, userAgent);
                throw ex;
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        } else {
            // User exists but has no password. We skip verification to allow
            log.info("LoginOrchestrator: Pure OAuth user detected (no password). Skipping password check to prompt linking.");
        }

        // If we reach here, the User exists and the password is correct if set.
        // Validate check (Blocked / Verified)
        try {
            userValidationService.validateUserStatus(user);
        } catch (Exception ex) {
            loginActivityService.recordFailure(email, ex.getMessage(), ip, userAgent);
            throw ex;
        }

        if (user == null) {
            log.warn("User unexpectedly null after validation");
            throw new IllegalStateException("User unexpectedly null after validation");
        }

        // Provider Check (Account Linking) user has already an account with OAuth provider now trying to log in using email
        if (!user.hasProvider(AuthProviderType.EMAIL)) {
            AuthProviderType existingProvider = user.getAuthProviders().iterator().next().getProviderType();
            log.warn("LoginOrchestrator: EMAIL provider not linked email={} existing={}", email, existingProvider);

            String linkToken = accountLinkTokenService.createLinkToken(user, AuthProviderType.EMAIL, email, false);

            return AuthenticationResult.builder()
                    .outcome(AuthOutcome.LINK_REQUIRED)
                    .email(email)
                    .existingProvider(existingProvider)
                    .attemptedProvider(AuthProviderType.EMAIL)
                    .nextAction(NextAction.LINK_ACCOUNT)
                    .linkToken(linkToken)
                    .message("This account uses " + existingProvider + ". Link email login?")
                    .build();
        }

        // Password Set Check
        if (user.getPassword() == null) {
            return AuthenticationResult.builder()
                    .outcome(AuthOutcome.PASSWORD_NOT_SET)
                    .email(email)
                    .nextAction(NextAction.SET_PASSWORD)
                    .message("Password not set. Please reset your password.")
                    .build();
        }

        // mfa Handling
        if (user.isMfaEnabled()) {
            log.info("LoginOrchestrator: MFA enabled for email={}", user.getEmail());
            MfaResult mfaResult = mfaService.handleMfaLogin(user);

            String msg = mfaResult.getEmailSent()
                    ? "OTP has been dispatched to your email address."
                    : "OTP email is being processed and will arrive shortly.";

            return AuthenticationResult.builder()
                    .outcome(AuthOutcome.MFA_REQUIRED)
                    .otpTokenId(mfaResult.getTokenId())
                    .message(msg)
                    .build();
        }

        // Risk Engine (Only for non-mfa users)
        RiskResult risk = riskEngineService.evaluateRisk(user, ip, userAgent);

        if (risk.getScore() >= highRiskScore) {
            log.error("LoginOrchestrator: HIGH RISK blocked email={} score={}", email, risk.getScore());
            throw riskEngineService.blockHighRiskLogin(user, risk, ip, userAgent);
        }

        if (risk.getScore() >= mediumRiskScore) {
            log.warn("LoginOrchestrator: MEDIUM RISK → OTP required email={}", email);
            MfaResult mfaResult = mfaService.handleMediumRiskOtp(user);

            String msg = mfaResult.getEmailSent()
                    ? "Suspicious login detected, verification required. OTP has been dispatched to your email address."
                    : "Suspicious login detected, verification required. Your OTP email is being processed and will arrive shortly.";

            return AuthenticationResult.builder()
                    .outcome(mfaResult.getOutcome())
                    .otpTokenId(mfaResult.getTokenId())
                    .message(msg)
                    .build();
        }

        // Successful login: Generate Tokens
        AuthenticationResult result = tokenService.generateTokens(user, ctx);

        eventPublisher.publishEvent(new LoginSuccessEvent(user.getId(), user.getEmail(), ip, userAgent));

        try {
            var agent = UserAgentParser.parse(userAgent);
            deviceTrustService.trustDevice(user.getId(), agent.getSignature(), agent.getDeviceName());
        } catch (Exception ex) {
            log.warn("LoginOrchestrator: failed to trust device", ex);
        }

        log.info("LoginOrchestrator: finished ip={} and email={}", ip, email);

        return AuthenticationResult.builder()
                .outcome(AuthOutcome.SUCCESS)
                .accessToken(result.getAccessToken())
                .refreshToken(result.getRefreshToken())
                .message("Login successful")
                .user(UserResponse.from(user))
                .build();
    }
}
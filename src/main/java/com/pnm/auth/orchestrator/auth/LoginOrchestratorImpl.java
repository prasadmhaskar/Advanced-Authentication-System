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
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import java.util.Optional;

//@Service
//@RequiredArgsConstructor
//@Slf4j
//public class LoginOrchestratorImpl implements LoginOrchestrator {
//
//    private final UserValidationService userValidationService;
//    private final PasswordAuthService passwordAuthService;
//    private final RiskEngineService riskEngineService;
//    private final MfaService mfaService;
//    private final TokenService tokenService;
//    private final DeviceTrustService deviceTrustService;
//    private final ApplicationEventPublisher eventPublisher;
//    private final AccountLinkTokenService accountLinkTokenService;
//    private final LoginActivityService loginActivityService;
//
//    private final SecureRandom secureRandom = new SecureRandom();
//
//    @Value("${auth.risk.threshold.high}")
//    private int highRiskScore;
//
//    @Value("${auth.risk.threshold.medium}")
//    private int mediumRiskScore;
//
//    @Override
//    public AuthenticationResult login(LoginRequest request, String ip, String userAgent) {
//
//        String email = request.getEmail().trim().toLowerCase();
//        log.info("LoginOrchestrator: login started email={}", email);
//
//        // ---------------------------------------------------------
//        // 1️⃣ Validate user existence + basic state (active, verified)
//        // ---------------------------------------------------------
//        User user;
//
//        try {
//            user = userValidationService.validateUserForLogin(email);
//        } catch (UserNotFoundException ex) {
//            loginActivityService.recordFailure(email,"User not found", ip, userAgent);
//            throw ex;
//        } catch (AccountBlockedException ex) {
//            loginActivityService.recordFailure(email, "Blocked user login attempt", ip, userAgent);
//            throw ex;
//        } catch (EmailNotVerifiedException ex) {
//            loginActivityService.recordFailure(email, "Email not verified", ip, userAgent);
//            throw ex;
//        }
//
//
//        // ---------------------------------------------------------
//        // 2️⃣ EMAIL provider not linked → OFFER LINKING
//        // ---------------------------------------------------------
//        if (!user.hasProvider(AuthProviderType.EMAIL)) {
//
//            AuthProviderType existingProvider =
//                    user.getAuthProviders().iterator().next().getProviderType();
//
//            log.warn(
//                    "Email login attempted but EMAIL provider not linked email={} existingProvider={}",
//                    email,
//                    existingProvider
//            );
//
//            String linkToken = accountLinkTokenService.createLinkToken(
//                    user,
//                    AuthProviderType.EMAIL,
//                    email
//            );
//
//            return AuthenticationResult.builder()
//                    .outcome(AuthOutcome.LINK_REQUIRED)
//                    .email(email)
//                    .existingProvider(existingProvider)
//                    .attemptedProvider(AuthProviderType.EMAIL)
//                    .nextAction(NextAction.LINK_ACCOUNT)
//                    .linkToken(linkToken)
//                    .message("This account uses a different login method. Link email login?")
//                    .build();
//        }
//
//        // ---------------------------------------------------------
//        // 3️⃣ Password not set → FORCE SET PASSWORD
//        // ---------------------------------------------------------
//        if (user.getPassword() == null) {
//
//            log.warn("Password not set for email login email={}", email);
//
//            return AuthenticationResult.builder()
//                    .outcome(AuthOutcome.PASSWORD_NOT_SET)
//                    .email(email)
//                    .nextAction(NextAction.SET_PASSWORD)
//                    .message("Password not set. Please set your password to continue.")
//                    .build();
//        }
//
//        // ---------------------------------------------------------
//        // 4️⃣ Verify password
//        // ---------------------------------------------------------
//        try {
//            passwordAuthService.verifyPassword(user, request.getPassword());
//        }catch (InvalidCredentialsException ex){
//            loginActivityService.recordFailure(email, "Wrong password entered", ip, userAgent);
//            throw ex;
//        }
//
//        // ---------------------------------------------------------
//        // 3️⃣ If MFA is enabled → handle MFA and return response
//        // ---------------------------------------------------------
//        if (user.isMfaEnabled()) {
//            log.info("LoginOrchestrator: MFA enabled for email={}", user.getEmail());
//            MfaResult mfaResult = mfaService.handleMfaLogin(user);
//
//            if (mfaResult.getEmailSent()){
//                return AuthenticationResult.builder()
//                        .outcome(AuthOutcome.MFA_REQUIRED)
//                        .otpTokenId(mfaResult.getTokenId())
//                        .message("Otp is sent to your email successfully. Please enter otp for verification")
//                        .build();
//            }
//            else {
//                return AuthenticationResult.builder()
//                        .outcome(AuthOutcome.MFA_REQUIRED)
//                        .otpTokenId(mfaResult.getTokenId())
//                        .message("Our email service is currently delayed. Please try resending in a few minutes.")
//                        .build();
//            }
//        }
//
//        // ---------------------------------------------------------
//        // 4️⃣ RUN RISK ENGINE (only for non-MFA users)
//        // ---------------------------------------------------------
//        RiskResult risk = riskEngineService.evaluateRisk(user, ip, userAgent);
//
//        if (risk.getScore() >= highRiskScore) {
//            log.error("LoginOrchestrator: HIGH RISK login blocked email={} score={}",
//                    user.getEmail(), risk.getScore());
//            throw riskEngineService.blockHighRiskLogin(user, risk, ip, userAgent);
//        }
//
//        if (risk.getScore() >= mediumRiskScore) {
//            log.warn("LoginOrchestrator: MEDIUM RISK → OTP required email={}", user.getEmail());
////            MfaResult mfaResult = handleMediumRiskOtp(user);
//            MfaResult mfaResult = mfaService.handleMediumRiskOtp(user);
//            if (mfaResult.getEmailSent()){
//                return AuthenticationResult.builder()
//                        .outcome(mfaResult.getOutcome())
//                        .otpTokenId(mfaResult.getTokenId())
//                        .message("Suspicious login detected. Please enter otp for verification")
//                        .build();
//            }
//            else {
//                return AuthenticationResult.builder()
//                        .outcome(mfaResult.getOutcome())
//                        .otpTokenId(mfaResult.getTokenId())
//                        .message("Suspicious login detected. Otp verification needed. Our email service is currently delayed. Please try resending in a few minutes.")
//                        .build();
//            }
//
//        }
//
//        // ---------------------------------------------------------
//        // 5️⃣ LOW RISK → SUCCESS: generate tokens
//        // ---------------------------------------------------------
//        AuthenticationResult result = tokenService.generateTokens(user);
//
//        //LoginActivity.recordSuccess()
//        eventPublisher.publishEvent(
//                new LoginSuccessEvent(
//                        user.getId(),
//                        user.getEmail(),
//                        ip,
//                        userAgent));
//
//        // ---------------------------------------------------------
//        // 6️⃣ Save trusted device (non-critical)
//        // ---------------------------------------------------------
//        try {
//            var agent = UserAgentParser.parse(userAgent);
//            deviceTrustService.trustDevice(
//                    user.getId(),
//                    agent.getSignature(),
//                    agent.getDeviceName()
//            );
//        } catch (Exception ex) {
//            log.warn("LoginOrchestrator: failed to trust device email={} err={}",
//                    user.getEmail(), ex.getMessage());
//        }
//
//        // ---------------------------------------------------------
//        // 7️⃣ Return SUCCESS response
//        // ---------------------------------------------------------
//        return AuthenticationResult.builder()
//                .outcome(AuthOutcome.SUCCESS)
//                .accessToken(result.getAccessToken())
//                .refreshToken(result.getRefreshToken())
//                .message("Login successful")
//                .user(UserResponse.from(user))
//                .build();
//
//    }
//
//}


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
    public AuthenticationResult login(LoginRequest request, String ip, String userAgent) {

        String email = request.getEmail().trim().toLowerCase();

        log.info("LoginOrchestrator: started for email={}", email);

        // ---------------------------------------------------------
        // 1️⃣ Load User (Silent)
        // ---------------------------------------------------------
        // We do NOT throw exceptions here if missing.
        Optional<User> userOpt = userValidationService.findUserByEmail(email);
        User user = userOpt.orElse(null);

        // 🚨 SPECIAL LOGIC: Handle Pure OAuth Users (Case 2)
        // If the user exists but has NO password (e.g., registered via Google),
        // checking the password is futile—it will always fail.
        // Instead, we SKIP the check so the flow falls through to "Step 4: Provider Check",
        // which correctly tells them: "Link your account" or "Use Google".
        boolean isPasswordSet = (user != null && user.getPassword() != null);

        // 2️⃣ Verify Password (Only if a password actually exists)
        if (user == null || isPasswordSet) {
            try {
                // If user is null, this runs a dummy hash (Timing Attack Protection)
                // If user has password, this verifies it.
                passwordAuthService.verifyPassword(user, request.getPassword());
            } catch (InvalidCredentialsException ex) {
                loginActivityService.recordFailure(email, "Invalid email or password", ip, userAgent);
                throw ex;
            }
        } else {
            // User exists but has NO password. We skip verification to allow
            // the "Link Account" logic (Step 4) to take over.
            log.info("LoginOrchestrator: Pure OAuth user detected (no password). Skipping password check to prompt linking.");
        }

        // ⭐ Security Note: If we reach here, the User exists AND Password is correct.
        // It is now safe to reveal specific account status errors.

        // ---------------------------------------------------------
        // 3️⃣ Validate Status (Blocked / Verified)
        // ---------------------------------------------------------
        try {
            userValidationService.validateUserStatus(user);
        } catch (Exception ex) {
            loginActivityService.recordFailure(email, ex.getMessage(), ip, userAgent);
            throw ex;
        }

        // ---------------------------------------------------------
        // 4️⃣ Provider Check (Account Linking)
        // ---------------------------------------------------------
        if (!user.hasProvider(AuthProviderType.EMAIL)) {
            AuthProviderType existingProvider = user.getAuthProviders().iterator().next().getProviderType();
            log.warn("LoginOrchestrator: EMAIL provider not linked email={} existing={}", email, existingProvider);

            String linkToken = accountLinkTokenService.createLinkToken(user, AuthProviderType.EMAIL, email);

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

        // ---------------------------------------------------------
        // 5️⃣ Password Set Check (Edge case)
        // ---------------------------------------------------------
        if (user.getPassword() == null) {
            return AuthenticationResult.builder()
                    .outcome(AuthOutcome.PASSWORD_NOT_SET)
                    .email(email)
                    .nextAction(NextAction.SET_PASSWORD)
                    .message("Password not set. Please reset your password.")
                    .build();
        }

        // ---------------------------------------------------------
        // 6️⃣ MFA Handling
        // ---------------------------------------------------------
        if (user.isMfaEnabled()) {
            log.info("LoginOrchestrator: MFA enabled for email={}", user.getEmail());
            // Since we removed @Transactional, the DB transaction inside mfaService closes immediately,
            // allowing the email future to complete without deadlock.
            MfaResult mfaResult = mfaService.handleMfaLogin(user);

            String msg = mfaResult.getEmailSent()
                    ? "OTP sent successfully."
                    : "OTP generated, email is on its way.";

            return AuthenticationResult.builder()
                    .outcome(AuthOutcome.MFA_REQUIRED)
                    .otpTokenId(mfaResult.getTokenId())
                    .message(msg)
                    .build();
        }

        // ---------------------------------------------------------
        // 7️⃣ Risk Engine (Only for non-MFA users)
        // ---------------------------------------------------------
        RiskResult risk = riskEngineService.evaluateRisk(user, ip, userAgent);

        if (risk.getScore() >= highRiskScore) {
            log.error("LoginOrchestrator: HIGH RISK blocked email={} score={}", email, risk.getScore());
            throw riskEngineService.blockHighRiskLogin(user, risk, ip, userAgent);
        }

        if (risk.getScore() >= mediumRiskScore) {
            log.warn("LoginOrchestrator: MEDIUM RISK → OTP required email={}", email);
            MfaResult mfaResult = mfaService.handleMediumRiskOtp(user);

            String msg = mfaResult.getEmailSent()
                    ? "Suspicious login detected, verification required. OTP sent successfully."
                    : "Suspicious login detected, verification required. OTP generated, email is on its way.";

            return AuthenticationResult.builder()
                    .outcome(mfaResult.getOutcome())
                    .otpTokenId(mfaResult.getTokenId())
                    .message(msg)
                    .build();
        }

        // ---------------------------------------------------------
        // 8️⃣ Success: Generate Tokens
        // ---------------------------------------------------------
        AuthenticationResult result = tokenService.generateTokens(user);

        eventPublisher.publishEvent(new LoginSuccessEvent(user.getId(), user.getEmail(), ip, userAgent));

        try {
            var agent = UserAgentParser.parse(userAgent);
            deviceTrustService.trustDevice(user.getId(), agent.getSignature(), agent.getDeviceName());
        } catch (Exception ex) {
            log.warn("LoginOrchestrator: failed to trust device", ex);
        }

        log.info("LoginOrchestrator: finished for email={}", email);

        return AuthenticationResult.builder()
                .outcome(AuthOutcome.SUCCESS)
                .accessToken(result.getAccessToken())
                .refreshToken(result.getRefreshToken())
                .message("Login successful")
                .user(UserResponse.from(user))
                .build();
    }
}
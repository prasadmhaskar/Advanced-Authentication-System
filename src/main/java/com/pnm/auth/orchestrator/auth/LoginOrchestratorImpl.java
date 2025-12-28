package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.domain.entity.MfaToken;
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
import com.pnm.auth.repository.MfaTokenRepository;
import com.pnm.auth.security.oauth.AccountLinkTokenService;
import com.pnm.auth.service.auth.MfaService;
import com.pnm.auth.service.auth.PasswordAuthService;
import com.pnm.auth.service.auth.TokenService;
import com.pnm.auth.service.auth.UserValidationService;
import com.pnm.auth.service.device.DeviceTrustService;
import com.pnm.auth.service.email.EmailService;
import com.pnm.auth.service.login.LoginActivityService;
import com.pnm.auth.service.risk.RiskEngineService;
import com.pnm.auth.util.AfterCommitExecutor;
import com.pnm.auth.util.UserAgentParser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;

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
    private final MfaTokenRepository mfaTokenRepository;
    private final EmailService emailService;
    private final AfterCommitExecutor afterCommitExecutor;
    private final LoginActivityService loginActivityService;

    private final SecureRandom secureRandom = new SecureRandom();

    @Value("${auth.risk.threshold.high}")
    private int highRiskScore;

    @Value("${auth.risk.threshold.medium}")
    private int mediumRiskScore;

    @Override
    @Transactional
    public AuthenticationResult login(LoginRequest request, String ip, String userAgent) {

        String email = request.getEmail().trim().toLowerCase();
        log.info("LoginOrchestrator: login started email={}", email);

        // ---------------------------------------------------------
        // 1️⃣ Validate user existence + basic state (active, verified)
        // ---------------------------------------------------------
        User user;

        try {
            user = userValidationService.validateUserForLogin(email);
        } catch (UserNotFoundException ex) {
            loginActivityService.recordFailure(email,"User not found", ip, userAgent);
            throw ex;
        } catch (AccountBlockedException ex) {
            loginActivityService.recordFailure(email, "Blocked user login attempt", ip, userAgent);
            throw ex;
        } catch (EmailNotVerifiedException ex) {
            loginActivityService.recordFailure(email, "Email not verified", ip, userAgent);
            throw ex;
        }


        // ---------------------------------------------------------
        // 2️⃣ EMAIL provider not linked → OFFER LINKING
        // ---------------------------------------------------------
        if (!user.hasProvider(AuthProviderType.EMAIL)) {

            AuthProviderType existingProvider =
                    user.getAuthProviders().iterator().next().getProviderType();

            log.warn(
                    "Email login attempted but EMAIL provider not linked email={} existingProvider={}",
                    email,
                    existingProvider
            );

            String linkToken = accountLinkTokenService.createLinkToken(
                    user,
                    AuthProviderType.EMAIL,
                    email
            );

            return AuthenticationResult.builder()
                    .outcome(AuthOutcome.LINK_REQUIRED)
                    .email(email)
                    .existingProvider(existingProvider)
                    .attemptedProvider(AuthProviderType.EMAIL)
                    .nextAction(NextAction.LINK_ACCOUNT)
                    .linkToken(linkToken)
                    .message("This account uses a different login method. Link email login?")
                    .build();
        }

        // ---------------------------------------------------------
        // 3️⃣ Password not set → FORCE SET PASSWORD
        // ---------------------------------------------------------
        if (user.getPassword() == null) {

            log.warn("Password not set for email login email={}", email);

            return AuthenticationResult.builder()
                    .outcome(AuthOutcome.PASSWORD_NOT_SET)
                    .email(email)
                    .nextAction(NextAction.SET_PASSWORD)
                    .message("Password not set. Please set your password to continue.")
                    .build();
        }

        // ---------------------------------------------------------
        // 4️⃣ Verify password
        // ---------------------------------------------------------
        try {
            passwordAuthService.verifyPassword(user, request.getPassword());
        }catch (InvalidCredentialsException ex){
            loginActivityService.recordFailure(email, "Wrong password entered", ip, userAgent);
            throw ex;
        }

        // ---------------------------------------------------------
        // 3️⃣ If MFA is enabled → handle MFA and return response
        // ---------------------------------------------------------
        if (user.isMfaEnabled()) {
            log.info("LoginOrchestrator: MFA enabled for email={}", user.getEmail());
            MfaResult mfaResult = handleMfaFlow(user);
            return AuthenticationResult.builder()
                    .outcome(AuthOutcome.MFA_REQUIRED)
                    .otpTokenId(mfaResult.getTokenId())
                    .message("Otp is sent to your email successfully. Please enter otp for verification")
                    .build();
        }

        // ---------------------------------------------------------
        // 4️⃣ RUN RISK ENGINE (only for non-MFA users)
        // ---------------------------------------------------------
        RiskResult risk = riskEngineService.evaluateRisk(user, ip, userAgent);

        if (risk.getScore() >= highRiskScore) {
            log.error("LoginOrchestrator: HIGH RISK login blocked email={} score={}",
                    user.getEmail(), risk.getScore());
            throw riskEngineService.blockHighRiskLogin(user, risk, ip, userAgent);
        }

        if (risk.getScore() >= mediumRiskScore) {
            log.warn("LoginOrchestrator: MEDIUM RISK → OTP required email={}", user.getEmail());
            MfaResult mfaResult = handleMediumRiskOtp(user);
            return AuthenticationResult.builder()
                    .outcome(mfaResult.getOutcome())
                    .otpTokenId(mfaResult.getTokenId())
                    .message("Suspicious login detected. Please enter otp for verification")
                    .build();
        }

        // ---------------------------------------------------------
        // 5️⃣ LOW RISK → SUCCESS: generate tokens
        // ---------------------------------------------------------
        AuthenticationResult result = tokenService.generateTokens(user);

        //LoginActivity.recordSuccess()
        eventPublisher.publishEvent(
                new LoginSuccessEvent(
                        user.getId(),
                        user.getEmail(),
                        ip,
                        userAgent));

        // ---------------------------------------------------------
        // 6️⃣ Save trusted device (non-critical)
        // ---------------------------------------------------------
        try {
            var agent = UserAgentParser.parse(userAgent);
            deviceTrustService.trustDevice(
                    user.getId(),
                    agent.getSignature(),
                    agent.getDeviceName()
            );
        } catch (Exception ex) {
            log.warn("LoginOrchestrator: failed to trust device email={} err={}",
                    user.getEmail(), ex.getMessage());
        }

        // ---------------------------------------------------------
        // 7️⃣ Return SUCCESS response
        // ---------------------------------------------------------
        return AuthenticationResult.builder()
                .outcome(AuthOutcome.SUCCESS)
                .accessToken(result.getAccessToken())
                .refreshToken(result.getRefreshToken())
                .message("Login successful")
                .user(UserResponse.from(user))
                .build();

    }

    // =====================================================================
    // Helper Methods
    // =====================================================================

    @Transactional
    private MfaResult handleMfaFlow(User user) {
        // 1. Generate OTP
        String otp = generateOtp();
        LocalDateTime expiresAt = LocalDateTime.now().plusMinutes(5);

        MfaToken token = new MfaToken();
        token.setUser(user);
        token.setOtp(otp);
        token.setExpiresAt(expiresAt);

        mfaTokenRepository.save(token);

        // 2. Send OTP asynchronously (AFTER COMMIT)
        afterCommitExecutor.run(() ->
                emailService.sendMfaOtpEmail(user.getEmail(), otp)
        );

        log.info("MfaService: OTP generated & sent for userId={}", user.getId());

        return MfaResult.builder()
                .outcome(AuthOutcome.OTP_REQUIRED)
                .tokenId(token.getId())
                .build();
    }

    private MfaResult handleMediumRiskOtp(User user) {

        MfaResult mfa = mfaService.handleMediumRiskOtp(user);

        if (mfa.getOutcome() == AuthOutcome.RISK_OTP_REQUIRED) {
            return MfaResult.builder()
                    .tokenId(mfa.getTokenId())
                    .outcome(mfa.getOutcome())
                    .build();
        }
        throw new IllegalStateException("Unexpected Risk OTP outcome");
    }


    private String generateOtp() {
        return String.format("%06d", secureRandom.nextInt(1_000_000));
    }

}

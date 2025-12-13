package com.pnm.auth.service.auth;

import com.pnm.auth.dto.request.LoginRequest;
import com.pnm.auth.dto.response.AuthResponse;
import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.dto.result.MfaResult;
import com.pnm.auth.dto.result.RiskResult;
import com.pnm.auth.entity.User;
import com.pnm.auth.enums.AuthOutcome;
import com.pnm.auth.exception.EmailSendFailedException;
import com.pnm.auth.exception.RiskOtpRequiredException;
import com.pnm.auth.util.UserAgentParser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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


    @Override
    @Transactional
    public AuthenticationResult login(LoginRequest request, String ip, String userAgent) {

        log.info("LoginOrchestrator: login started email={}", request.getEmail());

        // ---------------------------------------------------------
        // 1️⃣ Validate user existence + state (active, verified, etc)
        // ---------------------------------------------------------
        User user = userValidationService.validateUserForLogin(request.getEmail().trim().toLowerCase());

        // ---------------------------------------------------------
        // 2️⃣ Validate password (OAuth users blocked)
        // ---------------------------------------------------------
        passwordAuthService.verifyPassword(user, request.getPassword());

        // ---------------------------------------------------------
        // 3️⃣ If MFA is enabled → handle MFA and return response
        // ---------------------------------------------------------
        if (user.isMfaEnabled()) {
            log.info("LoginOrchestrator: MFA enabled for email={}", user.getEmail());
            return handleMfaFlow(user, ip, userAgent);
        }

        // ---------------------------------------------------------
        // 4️⃣ RUN RISK ENGINE (only for non-MFA users)
        // ---------------------------------------------------------
        RiskResult risk = riskEngineService.evaluateRisk(user, ip, userAgent);

        if (risk.getScore() >= 80) {
            log.error("LoginOrchestrator: HIGH RISK login blocked email={} score={}",
                    user.getEmail(), risk.getScore());
            throw riskEngineService.blockHighRiskLogin(user, risk, ip, userAgent);
        }

        if (risk.getScore() >= 40) {
            log.warn("LoginOrchestrator: MEDIUM RISK → OTP required email={}", user.getEmail());
            return handleMediumRiskOtp(user);
        }

        // ---------------------------------------------------------
        // 5️⃣ LOW RISK → SUCCESS: generate tokens
        // ---------------------------------------------------------
        AuthenticationResult result = tokenService.generateTokens(user);

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
                .user(user)
                .build();

    }

    // =====================================================================
    // Helper Methods
    // =====================================================================

    private AuthenticationResult handleMfaFlow(User user, String ip, String userAgent) {
        var mfa = mfaService.handleMfaLogin(user);
        if (mfa.getOutcome() == AuthOutcome.MFA_REQUIRED) {
            return AuthenticationResult.builder()
                    .outcome(AuthOutcome.MFA_REQUIRED)
                    .otpTokenId(mfa.getOtpTokenId())
                    .message("MFA verification needed")
                    .build();
        }
        throw new IllegalStateException("Unexpected MFA outcome");
    }

    private AuthenticationResult handleMediumRiskOtp(User user) {
        try {
            MfaResult mfa = mfaService.handleMediumRiskOtp(user);

            if (mfa.getOutcome() == AuthOutcome.RISK_OTP_REQUIRED) {
                throw new RiskOtpRequiredException(
                        "Suspicious login detected. OTP required.",
                        mfa.getTokenId()
                );
            }

            throw new IllegalStateException("Unexpected Risk OTP outcome");

        } catch (EmailSendFailedException ex) {
            throw ex;

        } catch (Exception ex) {
            log.error("LoginOrchestrator: medium-risk OTP error email={} err={}",
                    user.getEmail(), ex.getMessage(), ex);
            throw new EmailSendFailedException("Failed to send OTP. Try again later.");
        }
    }
}

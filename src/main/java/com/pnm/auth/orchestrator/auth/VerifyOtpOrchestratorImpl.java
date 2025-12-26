package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.request.OtpVerifyRequest;
import com.pnm.auth.dto.response.UserResponse;
import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.domain.entity.MfaToken;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.exception.custom.AccountBlockedException;
import com.pnm.auth.exception.custom.InvalidCredentialsException;
import com.pnm.auth.exception.custom.InvalidTokenException;
import com.pnm.auth.repository.MfaTokenRepository;
import com.pnm.auth.service.ipmonitoring.IpMonitoringService;
import com.pnm.auth.service.login.LoginActivityService;
import com.pnm.auth.service.auth.TokenService;
import com.pnm.auth.service.device.DeviceTrustService;
import com.pnm.auth.util.UserAgentParser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class VerifyOtpOrchestratorImpl implements VerifyOtpOrchestrator {

    private final MfaTokenRepository mfaTokenRepository;
    private final TokenService tokenService;
    private final DeviceTrustService deviceTrustService;
    private final LoginActivityService loginActivityService;
    private final IpMonitoringService ipMonitoringService;

    @Override
    @Transactional
    public AuthenticationResult verify(OtpVerifyRequest request, String ip, String userAgent) {

        log.info("VerifyOtpOrchestrator.verify(): started tokenId={}", request.getTokenId());

        // 1️⃣ Load OTP token
        MfaToken token = mfaTokenRepository.findByIdAndUsedFalse(request.getTokenId())
                .orElseThrow(() -> {
                    log.warn("VerifyOtpOrchestrator.verify(): token not found id={}", request.getTokenId());
                    return new InvalidTokenException("OTP token not found or already used");
                });

        User user = token.getUser();

        // 2️⃣ Validate user state
        if (!user.isActive()) {
            log.warn("VerifyOtpOrchestrator.verify(): blocked user tried to verify OTP email={}", user.getEmail());
            throw new AccountBlockedException("Your account has been blocked.");
        }

        // 3️⃣ Validate expiry
        if (token.getExpiresAt().isBefore(LocalDateTime.now())) {
            loginActivityService.recordFailure(user.getEmail(), "OTP expired", ip, userAgent);
            log.warn("VerifyOtpOrchestrator.verify(): token expired id={}", request.getTokenId());
            throw new InvalidTokenException("OTP expired");
        }

        // 4️⃣ Validate OTP
        if (!token.getOtp().equals(request.getOtp().trim())) {
            loginActivityService.recordFailure(user.getEmail(), "Wrong OTP", ip, userAgent);
            log.warn("VerifyOtpOrchestrator.verify(): wrong OTP for id={}", request.getTokenId());
            throw new InvalidCredentialsException("Invalid OTP");
        }

        // 5️⃣ Mark OTP as used
        token.setUsed(true);
        mfaTokenRepository.save(token);

        // 6️⃣ Record success
        loginActivityService.recordSuccess(user.getId(), user.getEmail(), ip, userAgent);

        // 7️⃣ Trust device (best-effort)
        try {
            var agent = UserAgentParser.parse(userAgent);
            deviceTrustService.trustDevice(
                    user.getId(),
                    agent.getSignature(),
                    agent.getDeviceName()
            );
        } catch (Exception ex) {
            log.warn("VerifyOtpOrchestrator.verify(): device trust failed userId={} msg={}", user.getId(), ex.getMessage());
        }

        // 9️⃣ Record IP risk (best-effort)
        try {
            ipMonitoringService.recordLogin(user.getId(), ip, userAgent);
        } catch (Exception ex) {
            log.warn("VerifyOtpOrchestrator.verify(): ipMonitoring failed userId={} msg={}", user.getId(), ex.getMessage());
        }

        // 8️⃣ Generate tokens
        AuthenticationResult tokens = tokenService.generateTokens(user);

        log.info("VerifyOtpOrchestrator.verify(): completed email={}", user.getEmail());

        String message = token.isRiskBased()
                ? "Risk-based OTP verified successfully"
                : "MFA OTP verified successfully";

        return AuthenticationResult.builder()
                .outcome(AuthOutcome.SUCCESS)
                .accessToken(tokens.getAccessToken())
                .refreshToken(tokens.getRefreshToken())
                .message(message)
                .user(UserResponse.from(user))
                .build();
    }
}


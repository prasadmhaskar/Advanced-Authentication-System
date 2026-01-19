package com.pnm.auth.orchestrator.auth.impl;

import com.pnm.auth.dto.request.OtpVerifyRequest;
import com.pnm.auth.dto.response.UserResponse;
import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.domain.entity.MfaToken;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.event.FailureEvent;
import com.pnm.auth.event.SuccessEvent;
import com.pnm.auth.exception.custom.AccountBlockedException;
import com.pnm.auth.exception.custom.InvalidCredentialsException;
import com.pnm.auth.exception.custom.InvalidTokenException;
import com.pnm.auth.orchestrator.auth.VerifyOtpOrchestrator;
import com.pnm.auth.repository.MfaTokenRepository;
import com.pnm.auth.service.interfaces.ipmonitoring.IpMonitoringService;
import com.pnm.auth.service.interfaces.login.ActivityService;
import com.pnm.auth.service.interfaces.auth.TokenService;
import com.pnm.auth.service.interfaces.device.DeviceTrustService;
import com.pnm.auth.util.MaskingUtil;
import com.pnm.auth.util.UserAgentParser;
import com.pnm.auth.web.context.RequestContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
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
    private final IpMonitoringService ipMonitoringService;
    private final ApplicationEventPublisher eventPublisher;

    @Override
    @Transactional
    public AuthenticationResult verify(OtpVerifyRequest request, RequestContext ctx) {

        String ip = ctx.ip();
        String userAgent = ctx.userAgent();

        log.info("VerifyOtpOrchestrator: started");

        // Load otp token
        MfaToken token = mfaTokenRepository.findByIdAndUsedFalse(request.getTokenId())
                .orElseThrow(() -> {
                    log.warn("VerifyOtpOrchestrator: token not found id={}", request.getTokenId());
                    return new InvalidTokenException("OTP token not found or already used");
                });

        // Load user
        User user = token.getUser();

        // Validate user status
        if (!user.isActive()) {
            log.warn("VerifyOtpOrchestrator: blocked user tried to verify OTP email={}", MaskingUtil.maskEmail(user.getEmail()));
            eventPublisher.publishEvent(new FailureEvent(user.getId(), user.getEmail(), ip, userAgent, "Blocked user tried to verify OTP"));
            throw new AccountBlockedException("Your account has been blocked.");
        }

        // Validate otp expiry
        if (token.getExpiresAt().isBefore(LocalDateTime.now())) {
            log.warn("VerifyOtpOrchestrator: token expired id={}", request.getTokenId());
            throw new InvalidTokenException("OTP expired");
        }

        // Validate otp
        if (!token.getOtp().equals(request.getOtp().trim())) {
            log.warn("VerifyOtpOrchestrator: wrong OTP for id={}", request.getTokenId());
            throw new InvalidCredentialsException("Invalid OTP");
        }

        // Mark otp as used
        int rowsUpdated = mfaTokenRepository.markAsUsed(token.getId());
        if (rowsUpdated == 0) {
            log.warn("VerifyOtpOrchestrator: OTP already user for id={}", request.getTokenId());
            throw new InvalidTokenException("OTP already used");
        }

        // Trust device
        try {
            var agent = UserAgentParser.parse(userAgent);
            deviceTrustService.trustDevice(
                    user.getId(),
                    agent.getSignature(),
                    agent.getDeviceName()
            );
        } catch (Exception ex) {
            log.warn("VerifyOtpOrchestrator: device trust failed userId={} msg={}", user.getId(), ex.getMessage());
        }

        // Record ip risk
        try {
            ipMonitoringService.recordIpDetails(user.getId(), ip, userAgent);
        } catch (Exception ex) {
            log.warn("VerifyOtpOrchestrator: ipMonitoring failed userId={} msg={}", user.getId(), ex.getMessage());
        }

        eventPublisher.publishEvent(new SuccessEvent(user.getId(), user.getEmail(), ip, userAgent, "OTP verified successfully"));

        // Generate tokens
        AuthenticationResult tokens = tokenService.generateTokens(user, ctx);

        log.info("VerifyOtpOrchestrator: finished for email={}", MaskingUtil.maskEmail(user.getEmail()));

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


package com.pnm.auth.orchestrator.auth.impl;

import com.pnm.auth.dto.request.OtpResendRequest;
import com.pnm.auth.domain.entity.MfaToken;
import com.pnm.auth.dto.response.ResendOtpResponse;
import com.pnm.auth.exception.custom.CooldownActiveException;
import com.pnm.auth.exception.custom.InvalidTokenException;
import com.pnm.auth.orchestrator.auth.interfaces.ResendOtpOrchestrator;
import com.pnm.auth.repository.MfaTokenRepository;
import com.pnm.auth.service.interfaces.auth.MfaPersistenceService;
import com.pnm.auth.service.interfaces.email.EmailService;
import com.pnm.auth.service.impl.redis.RedisCooldownService;
import com.pnm.auth.util.MaskingUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import java.time.Duration;

@Service
@RequiredArgsConstructor
@Slf4j
public class ResendOtpOrchestratorImpl implements ResendOtpOrchestrator {

    private final MfaPersistenceService mfaPersistenceService;
    private final EmailService emailService;
    private final RedisCooldownService cooldownService;
    private final MfaTokenRepository mfaTokenRepository;

    @Override
    public ResendOtpResponse resend(OtpResendRequest request) {

        log.info("ResendOtpOrchestrator: started");

        MfaToken existingToken = mfaTokenRepository.findByIdAndUsedFalse(request.getTokenId()).orElseThrow(() -> {
            log.warn("MfaPersistence: token not found or already used");
            return new InvalidTokenException("OTP token not found or already used");
        });

        Long userId = existingToken.getUser().getId();

        // User can send otp once per 60 seconds - Checking in redis that how much time is remaining for expiring previous otp token
        String cooldownKey = "MFA_RESEND_COOLDOWN:USER:" + userId;

        if (cooldownService.isInCooldown(cooldownKey)) {
            long remaining = cooldownService.getRemainingSeconds(cooldownKey);
            throw new CooldownActiveException(
                    "Please wait " + remaining + " seconds before resending OTP"
            );
        }

        // Rotate Token
        MfaToken newToken = mfaPersistenceService.rotateMfaToken(existingToken);
        String email = newToken.getUser().getEmail();

        // Start cooldown for 60 seconds
        cooldownService.startCooldown(cooldownKey, Duration.ofSeconds(60));

        // Send email
        emailService.sendMfaOtpEmail(email, newToken.getOtp());

        log.info("ResendOtpOrchestrator: finished for email={}", MaskingUtil.maskEmail(email));

        return ResendOtpResponse.builder()
                .newTokenId(newToken.getId())
                .build();
    }
}
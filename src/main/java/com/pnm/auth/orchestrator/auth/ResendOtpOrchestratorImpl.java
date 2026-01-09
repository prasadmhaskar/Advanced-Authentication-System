package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.request.OtpResendRequest;
import com.pnm.auth.domain.entity.MfaToken;
import com.pnm.auth.dto.response.ResendOtpResponse;
import com.pnm.auth.exception.custom.CooldownActiveException;
import com.pnm.auth.exception.custom.InvalidTokenException;
import com.pnm.auth.repository.MfaTokenRepository;
import com.pnm.auth.service.auth.MfaPersistenceService;
import com.pnm.auth.service.email.EmailService;
import com.pnm.auth.service.impl.redis.RedisCooldownService;
import com.pnm.auth.util.AuthUtil;
import com.pnm.auth.web.context.RequestContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

@Service
@RequiredArgsConstructor
@Slf4j
public class ResendOtpOrchestratorImpl implements ResendOtpOrchestrator {

    private final MfaPersistenceService mfaPersistenceService;
    private final EmailService emailService;
    private final RedisCooldownService cooldownService;
    private final MfaTokenRepository mfaTokenRepository;

    @Value("${email.send.timeout.ms}")
    private long emailTimeout;

    @Override
    public ResendOtpResponse resend(OtpResendRequest request, RequestContext ctx) {

        log.info("ResendOtpOrchestrator: started ip={}", ctx.ip());

        MfaToken existingToken = mfaTokenRepository.findByIdAndUsedFalse(request.getTokenId()).orElseThrow(() -> {
            log.warn("MfaPersistence: token not found or already used ip={}", ctx.ip());
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

        // Send Email
        CompletableFuture<Boolean> emailResultFuture = emailService.sendMfaOtpEmail(email, newToken.getOtp());

        boolean emailSent;
        try {
            emailSent = emailResultFuture.get(4000, TimeUnit.MILLISECONDS);

        } catch (TimeoutException e) {
            log.warn("ResendOtpOrchestrator: Email timed out. User will receive it eventually.");
            emailSent = false;

        } catch (ExecutionException e) {
            log.error("ResendOtpOrchestrator: CRITICAL EMAIL FAILURE. Cause: {}", e.getCause().getMessage());
            emailSent = false;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            emailSent = false;
        }

        // Set cooldown, add new otp token id in redis for 60 seconds
         if (emailSent) {
            cooldownService.startCooldown(
                    cooldownKey,
                    Duration.ofSeconds(60)
            );
        }

        log.info("ResendOtpOrchestrator: finished ip={} and email={} emailSentInTime={}",ctx.ip(), email, emailSent);

        return ResendOtpResponse.builder()
                .emailSent(emailSent)
                .newTokenId(newToken.getId())
                .build();
    }
}
package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.request.OtpResendRequest;
import com.pnm.auth.domain.entity.MfaToken;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.dto.response.ResendOtpResponse;
import com.pnm.auth.exception.custom.AccountBlockedException;
import com.pnm.auth.exception.custom.CooldownActiveException;
import com.pnm.auth.exception.custom.EmailSendFailedException;
import com.pnm.auth.exception.custom.InvalidTokenException;
import com.pnm.auth.repository.MfaTokenRepository;
import com.pnm.auth.service.email.EmailService;
import com.pnm.auth.service.impl.redis.RedisCooldownService;
import com.pnm.auth.util.AfterCommitExecutor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class ResendOtpOrchestratorImpl implements ResendOtpOrchestrator {

    private final MfaTokenRepository mfaTokenRepository;
    private final EmailService emailService;
    private final AfterCommitExecutor afterCommitExecutor;
    private final RedisCooldownService cooldownService;

    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    @Transactional
    public ResendOtpResponse resend(OtpResendRequest request) {

        String cooldownKey = "MFA_RESEND_COOLDOWN:" + request.getTokenId();

        if (cooldownService.isInCooldown(cooldownKey)) {
            long remaining = cooldownService.getRemainingSeconds(cooldownKey);
            throw new CooldownActiveException(
                    "Please wait " + remaining + " seconds before resending OTP"
            );
        }

        log.info("ResendOtpOrchestrator: resend started tokenId={}", request.getTokenId());

        // 1️⃣ Load existing OTP token
        MfaToken oldToken = mfaTokenRepository.findByIdAndUsedFalse(request.getTokenId())
                .orElseThrow(() -> {
                    log.warn("ResendOtpOrchestrator: token not found id={}", request.getTokenId());
                    return new InvalidTokenException("OTP session expired. Please login again.");
                });

        User user = oldToken.getUser();

        // 2️⃣ Validate user state
        if (!user.isActive()) {
            log.warn("ResendOtpOrchestrator: blocked user attempted resend email={}", user.getEmail());
            throw new AccountBlockedException("Your account has been blocked.");
        }

            // 3️⃣ Invalidate old OTP
            oldToken.setUsed(true);
            mfaTokenRepository.save(oldToken);

            // 4️⃣ Generate new OTP
            String otp = String.format("%06d", secureRandom.nextInt(1_000_000));

            MfaToken newToken = new MfaToken();
            newToken.setUser(user);
            newToken.setOtp(otp);
            newToken.setRiskBased(oldToken.isRiskBased());
            newToken.setExpiresAt(LocalDateTime.now().plusMinutes(5));
            newToken.setUsed(false);

            mfaTokenRepository.save(newToken);

            // 5️⃣ Send OTP email (resilience + retry handled inside EmailService)
        CompletableFuture<Boolean> emailResultFuture = new CompletableFuture<>();

        afterCommitExecutor.run(() -> {
            emailService.sendMfaOtpEmail(user.getEmail(), newToken.getOtp())
                    .thenAccept(emailResultFuture::complete)
                    .exceptionally(ex -> {
                        emailResultFuture.complete(false);
                        return null;
                    });
        });

        boolean emailSent;
        try {
            emailSent = emailResultFuture.get(2, TimeUnit.SECONDS);
        } catch (Exception e) {
            emailSent = false;
        }

            cooldownKey = "MFA_RESEND_COOLDOWN:" + newToken.getId();

        if (emailSent) {
            cooldownService.startCooldown(
                    cooldownKey,
                    Duration.ofSeconds(60)
            );
        }

        log.info("ResendOtpOrchestrator: resend finished email={} emailSent={}", user.getEmail(), emailSent);

            return ResendOtpResponse.builder()
                    .emailSent(emailSent)
                    .build();
    }
}
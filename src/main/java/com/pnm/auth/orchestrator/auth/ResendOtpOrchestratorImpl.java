package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.request.OtpResendRequest;
import com.pnm.auth.domain.entity.MfaToken;
import com.pnm.auth.dto.response.ResendOtpResponse;
import com.pnm.auth.exception.custom.CooldownActiveException;
import com.pnm.auth.service.auth.MfaPersistenceService;
import com.pnm.auth.service.email.EmailService;
import com.pnm.auth.service.impl.redis.RedisCooldownService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

//@Service
//@RequiredArgsConstructor
//@Slf4j
//public class ResendOtpOrchestratorImpl implements ResendOtpOrchestrator {
//
//    private final MfaTokenRepository mfaTokenRepository;
//    private final EmailService emailService;
//    private final AfterCommitExecutor afterCommitExecutor;
//    private final RedisCooldownService cooldownService;
//
//    private final SecureRandom secureRandom = new SecureRandom();
//
//    @Override
//    @Transactional
//    public ResendOtpResponse resend(OtpResendRequest request) {
//
//        String cooldownKey = "MFA_RESEND_COOLDOWN:" + request.getTokenId();
//
//        if (cooldownService.isInCooldown(cooldownKey)) {
//            long remaining = cooldownService.getRemainingSeconds(cooldownKey);
//            throw new CooldownActiveException(
//                    "Please wait " + remaining + " seconds before resending OTP"
//            );
//        }
//
//        log.info("ResendOtpOrchestrator: resend started tokenId={}", request.getTokenId());
//
//        // 1️⃣ Load existing OTP token
//        MfaToken oldToken = mfaTokenRepository.findByIdAndUsedFalse(request.getTokenId())
//                .orElseThrow(() -> {
//                    log.warn("ResendOtpOrchestrator: token not found id={}", request.getTokenId());
//                    return new InvalidTokenException("OTP session expired. Please login again.");
//                });
//
//        User user = oldToken.getUser();
//
//        // 2️⃣ Validate user state
//        if (!user.isActive()) {
//            log.warn("ResendOtpOrchestrator: blocked user attempted resend email={}", user.getEmail());
//            throw new AccountBlockedException("Your account has been blocked.");
//        }
//
//            // 3️⃣ Invalidate old OTP
//            oldToken.setUsed(true);
//            mfaTokenRepository.save(oldToken);
//
//            // 4️⃣ Generate new OTP
//            String otp = String.format("%06d", secureRandom.nextInt(1_000_000));
//
//            MfaToken newToken = new MfaToken();
//            newToken.setUser(user);
//            newToken.setOtp(otp);
//            newToken.setRiskBased(oldToken.isRiskBased());
//            newToken.setExpiresAt(LocalDateTime.now().plusMinutes(5));
//            newToken.setUsed(false);
//
//            mfaTokenRepository.save(newToken);
//
//            // 5️⃣ Send OTP email (resilience + retry handled inside EmailService)
//        CompletableFuture<Boolean> emailResultFuture = new CompletableFuture<>();
//
//        afterCommitExecutor.run(() -> {
//            emailService.sendMfaOtpEmail(user.getEmail(), newToken.getOtp())
//                    .thenAccept(emailResultFuture::complete)
//                    .exceptionally(ex -> {
//                        emailResultFuture.complete(false);
//                        return null;
//                    });
//        });
//
//        boolean emailSent;
//        try {
//            emailSent = emailResultFuture.get(2, TimeUnit.SECONDS);
//        } catch (Exception e) {
//            emailSent = false;
//        }
//
//            cooldownKey = "MFA_RESEND_COOLDOWN:" + newToken.getId();
//
//        if (emailSent) {
//            cooldownService.startCooldown(
//                    cooldownKey,
//                    Duration.ofSeconds(60)
//            );
//        }
//
//        log.info("ResendOtpOrchestrator: resend finished email={} emailSent={}", user.getEmail(), emailSent);
//
//            return ResendOtpResponse.builder()
//                    .emailSent(emailSent)
//                    .build();
//    }
//}


@Service
@RequiredArgsConstructor
@Slf4j
public class ResendOtpOrchestratorImpl implements ResendOtpOrchestrator {

    private final MfaPersistenceService mfaPersistenceService; // 👈 Use the service
    private final EmailService emailService;
    private final RedisCooldownService cooldownService;

    @Override
    public ResendOtpResponse resend(OtpResendRequest request) {

        String cooldownKey = "MFA_RESEND_COOLDOWN:" + request.getTokenId();

        if (cooldownService.isInCooldown(cooldownKey)) {
            long remaining = cooldownService.getRemainingSeconds(cooldownKey);
            throw new CooldownActiveException(
                    "Please wait " + remaining + " seconds before resending OTP"
            );
        }

        log.info("ResendOtpOrchestrator: resend started tokenId={}", request.getTokenId());

        // 1️⃣ Rotate Token (DB Transaction runs and commits inside this line)
        MfaToken newToken = mfaPersistenceService.rotateMfaToken(request.getTokenId());
        String email = newToken.getUser().getEmail();

        // 2️⃣ Send Email (Now runs outside any DB lock)
        CompletableFuture<Boolean> emailResultFuture = emailService.sendMfaOtpEmail(email, newToken.getOtp());

        boolean emailSent;
        try {
            emailSent = emailResultFuture.get(1000, TimeUnit.MILLISECONDS);

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

        // 3️⃣ Set Cooldown (Use the NEW token ID for the next cooldown check?)
        // Note: You might want to cool down logic on the USER ID or IP to prevent token hopping,
        // but sticking to your current logic:
        if (emailSent) {
            cooldownService.startCooldown(
                    "MFA_RESEND_COOLDOWN:" + newToken.getId(),
                    Duration.ofSeconds(60)
            );
        }


        log.info("ResendOtpOrchestrator: resend finished email={} emailSent={}", email, emailSent);

        return ResendOtpResponse.builder()
                .emailSent(emailSent)
                .newTokenId(newToken.getId()) // 👈 CRITICAL: Frontend needs the new ID to verify!
                .build();
    }
}
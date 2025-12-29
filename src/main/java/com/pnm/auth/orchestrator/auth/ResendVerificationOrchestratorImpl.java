package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.entity.VerificationToken;
import com.pnm.auth.domain.enums.NextAction;
import com.pnm.auth.domain.enums.ResendVerificationOutcome;
import com.pnm.auth.dto.result.ResendVerificationResult;
import com.pnm.auth.exception.custom.TooManyRequestsException;
import com.pnm.auth.exception.custom.UserNotFoundException;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.repository.VerificationTokenRepository;
import com.pnm.auth.service.auth.VerificationService;
import com.pnm.auth.service.email.EmailService;
import com.pnm.auth.service.login.LoginActivityService;
import com.pnm.auth.service.redis.RedisRateLimiterService;
import com.pnm.auth.util.AfterCommitExecutor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class ResendVerificationOrchestratorImpl implements ResendVerificationOrchestrator {

    private final UserRepository userRepository;
    private final VerificationTokenRepository verificationTokenRepository;
    private final VerificationService verificationService;
    private final EmailService emailService;
    private final LoginActivityService loginActivityService;
    private final RedisRateLimiterService redisRateLimiterService;
    private final AfterCommitExecutor afterCommitExecutor;
    private final StringRedisTemplate redisTemplate;

    @Override
    @Transactional
    public ResendVerificationResult resend(String email, String ip, String userAgent) {

        log.info("ResendVerificationOrchestrator: started email={}", email);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("ResendVerificationOrchestrator: user not found email={}", email);
                    loginActivityService.recordFailure(email, "User not found", ip, userAgent);
                    return new UserNotFoundException("User not found with email: " + email);
                });

        // ✅ Idempotency: already verified
        if (user.getEmailVerified()) {
            log.info("ResendVerificationOrchestrator: email already verified email={}", email);
            return ResendVerificationResult.builder()
                    .outcome(ResendVerificationOutcome.ALREADY_VERIFIED)
                    .email(email)
                    .nextAction(NextAction.LOGIN)
                    .build();
        }

        // 🔥 Invalidate previous unused tokens
        verificationTokenRepository.invalidateUnusedTokens(
                user.getId(), "EMAIL_VERIFICATION");

        // 🔐 EMAIL-BASED COOLDOWN (CRITICAL)
        String key = "resend:verify:" + email.toLowerCase();

        boolean allowed = redisRateLimiterService.isAllowed(key, 1, 120);

        if (!allowed) {
            throw new TooManyRequestsException(
                    "Please wait 2 minutes before requesting another email."
            );
        }

        String token = verificationService.createVerificationToken(user, "EMAIL_VERIFICATION");

        // Send email

        CompletableFuture<Boolean> emailResultFuture = new CompletableFuture<>();

        afterCommitExecutor.run(() -> {
            // This runs after DB commit
            emailService.sendVerificationEmail(email, token)
                    .thenAccept(emailResultFuture::complete)
                    .exceptionally(ex -> {
                        emailResultFuture.complete(false);
                        return null;
                    });
        });

// Now we wait for the email result (with a timeout so we don't hang the API)
        boolean emailSent;
        try {
            // 2 seconds is plenty for an async handoff/circuit breaker check
            emailSent = emailResultFuture.get(2, TimeUnit.SECONDS);
        } catch (Exception e) {
            emailSent = false;
        }

        // ⭐ CRITICAL FIX: If email failed, "refund" the rate limit token
        if (!emailSent) {
            redisTemplate.delete("rate_limit:" + key);
            log.warn("Email failed to send. Rate limit reset for email={}", email);
        }

        log.info("ResendVerificationOrchestrator: verification email resent to email={}. Email sent={}", email, emailSent);

        return ResendVerificationResult.builder()
                .outcome(ResendVerificationOutcome.EMAIL_SENT)
                .email(email)
                .nextAction(NextAction.VERIFY_EMAIL)
                .emailSent(emailSent)
                .build();
    }
}


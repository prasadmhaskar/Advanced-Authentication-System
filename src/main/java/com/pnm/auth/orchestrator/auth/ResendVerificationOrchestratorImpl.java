package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.NextAction;
import com.pnm.auth.domain.enums.ResendVerificationOutcome;
import com.pnm.auth.dto.result.ResendVerificationResult;
import com.pnm.auth.exception.custom.TooManyRequestsException;
import com.pnm.auth.exception.custom.UserNotFoundException;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.service.auth.VerificationService;
import com.pnm.auth.service.email.EmailService;
import com.pnm.auth.service.login.LoginActivityService;
import com.pnm.auth.service.redis.RedisRateLimiterService;
import com.pnm.auth.web.context.RequestContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;


@Service
@RequiredArgsConstructor
@Slf4j
public class ResendVerificationOrchestratorImpl implements ResendVerificationOrchestrator {

    private final UserRepository userRepository;
    private final VerificationService verificationService;
    private final EmailService emailService;
    private final LoginActivityService loginActivityService;
    private final RedisRateLimiterService redisRateLimiterService;

    @Value("${email.send.timeout.ms}")
    private long emailTimeout;


    @Override
    public ResendVerificationResult resend(String email, RequestContext ctx) {

        String ip = ctx.ip();
        String userAgent = ctx.userAgent();

        log.info("ResendVerificationOrchestrator: started ip={} and email={}", ip, email);

        // Find User
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("ResendVerificationOrchestrator: user not found email={}", email);
                    loginActivityService.recordFailure(email, "User not found", ip, userAgent);
                    return new UserNotFoundException("User not found with email: " + email);
                });

        // Idempotency Check
        if (user.getEmailVerified()) {
            log.info("ResendVerificationOrchestrator: email already verified email={}", email);
            return ResendVerificationResult.builder()
                    .outcome(ResendVerificationOutcome.ALREADY_VERIFIED)
                    .email(email)
                    .nextAction(NextAction.LOGIN)
                    .build();
        }

        // Rate Limit Check (User can only request a new verification link after 120 seconds completed for previous request)
        String key = "resend:verify:" + email.toLowerCase();
        boolean allowed = redisRateLimiterService.isAllowed(key, 1, 120);

        if (!allowed) {
            throw new TooManyRequestsException(
                    "Please wait 2 minutes before requesting another email."
            );
        }

        // Create Token
        String token = verificationService.createVerificationToken(user, "EMAIL_VERIFICATION");

        // Send Email
        CompletableFuture<Boolean> emailResultFuture = emailService.sendVerificationEmail(email, token);

        boolean emailSent;
        try {
            emailSent = emailResultFuture.get(emailTimeout, TimeUnit.MILLISECONDS);

        } catch (TimeoutException e) {
            // Server is slow.
            log.warn("ResendVerificationOrchestrator: Email timed out. User will receive it eventually.");
            emailSent = false;

        } catch (ExecutionException e) {
            // The System is BROKEN.
            log.error("ResendVerificationOrchestrator: CRITICAL EMAIL FAILURE. Cause: {}", e.getCause().getMessage());
            emailSent = false;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            emailSent = false;
        }

        // Refund Rate Limit if Email Fails
        if (!emailSent) {
            redisRateLimiterService.refund(key);
            log.warn("Email failed to send. Rate limit reset for email={}", email);
        }

        log.info("ResendVerificationOrchestrator: finished ip={} and email={}, emailSentWithInTime={}",ip, email, emailSent);

        return ResendVerificationResult.builder()
                .outcome(ResendVerificationOutcome.EMAIL_SENT)
                .email(email)
                .nextAction(NextAction.VERIFY_EMAIL)
                .emailSent(emailSent)
                .build();
    }
}
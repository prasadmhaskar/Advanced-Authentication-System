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
import org.springframework.stereotype.Service;

import java.util.concurrent.CompletableFuture;


@Service
@RequiredArgsConstructor
@Slf4j
public class ResendVerificationOrchestratorImpl implements ResendVerificationOrchestrator {

    private final UserRepository userRepository;
    private final VerificationService verificationService;
    private final EmailService emailService;
    private final LoginActivityService loginActivityService;
    private final RedisRateLimiterService redisRateLimiterService;


    @Override
    public ResendVerificationResult resend(String email, RequestContext ctx) {

        log.info("ResendVerificationOrchestrator: started for email={}", email);

        // Find User
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("ResendVerificationOrchestrator: user not found email={}", email);
                    loginActivityService.recordFailure(email, "User not found", ctx.ip(), ctx.userAgent());
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
        emailService.sendVerificationEmail(email, token);

        log.info("ResendVerificationOrchestrator: finished for email={}", email);

        return ResendVerificationResult.builder()
                .outcome(ResendVerificationOutcome.EMAIL_SENT)
                .email(email)
                .nextAction(NextAction.VERIFY_EMAIL)
                .build();
    }
}
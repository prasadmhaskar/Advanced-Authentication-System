package com.pnm.auth.orchestrator.auth.impl;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.NextAction;
import com.pnm.auth.domain.enums.ResendVerificationOutcome;
import com.pnm.auth.dto.result.ResendVerificationResult;
import com.pnm.auth.event.FailureEvent;
import com.pnm.auth.exception.custom.TooManyRequestsException;
import com.pnm.auth.exception.custom.UserNotFoundException;
import com.pnm.auth.orchestrator.auth.ResendVerificationOrchestrator;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.service.interfaces.auth.VerificationService;
import com.pnm.auth.service.interfaces.email.EmailService;
import com.pnm.auth.service.interfaces.login.ActivityService;
import com.pnm.auth.service.interfaces.redis.RedisRateLimiterService;
import com.pnm.auth.util.MaskingUtil;
import com.pnm.auth.web.context.RequestContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
@Slf4j
public class ResendVerificationOrchestratorImpl implements ResendVerificationOrchestrator {

    private final UserRepository userRepository;
    private final VerificationService verificationService;
    private final EmailService emailService;
    private final RedisRateLimiterService redisRateLimiterService;

    @Override
    public ResendVerificationResult resend(String email, RequestContext ctx) {

        log.info("ResendVerificationOrchestrator: started for email={}", MaskingUtil.maskEmail(email));

        // Find User
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("ResendVerificationOrchestrator: user not found email={}", MaskingUtil.maskEmail(email));
                    return new UserNotFoundException("User not found with email: " + MaskingUtil.maskEmail(email));
                });

        // Idempotency Check
        if (user.getEmailVerified()) {
            log.info("ResendVerificationOrchestrator: email already verified email={}", MaskingUtil.maskEmail(email));
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

        log.info("ResendVerificationOrchestrator: finished for email={}", MaskingUtil.maskEmail(email));

        return ResendVerificationResult.builder()
                .outcome(ResendVerificationOutcome.EMAIL_SENT)
                .email(email)
                .nextAction(NextAction.VERIFY_EMAIL)
                .build();
    }
}
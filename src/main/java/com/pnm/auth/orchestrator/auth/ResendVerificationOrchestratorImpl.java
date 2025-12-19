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
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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

    @Override
    @Transactional
    public ResendVerificationResult resend(String email) {

        log.info("ResendVerificationOrchestrator: started email={}", email);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("ResendVerificationOrchestrator: user not found email={}", email);
                    loginActivityService.recordFailure(email, "User not found");
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
                    "Please wait before requesting another verification email"
            );
        }

        String token = verificationService.createVerificationToken(user, "EMAIL_VERIFICATION");

        // ✅ Send email
        afterCommitExecutor.run(() ->
                emailService.sendVerificationEmail(email, token)
        );


        log.info("ResendVerificationOrchestrator: verification email resent email={}", email);

        return ResendVerificationResult.builder()
                .outcome(ResendVerificationOutcome.EMAIL_SENT)
                .email(email)
                .nextAction(NextAction.VERIFY_EMAIL)
                .build();
    }
}


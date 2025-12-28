package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.result.ForgotPasswordResult;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuditAction;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.exception.custom.EmailSendFailedException;
import com.pnm.auth.exception.custom.UserNotFoundException;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.service.email.EmailService;
import com.pnm.auth.service.auth.VerificationService;
import com.pnm.auth.util.AfterCommitExecutor;
import com.pnm.auth.util.Audit;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class ForgotPasswordOrchestratorImpl implements ForgotPasswordOrchestrator {

    private final UserRepository userRepository;
    private final VerificationService verificationService;
    private final EmailService emailService;
    private final AfterCommitExecutor afterCommitExecutor;

    @Override
    public ForgotPasswordResult requestReset(String rawEmail) {

        String email = rawEmail.trim().toLowerCase();
        log.info("ForgotPasswordOrchestrator: started email={}", email);

        // 1️⃣ Validate user existence
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("ForgotPasswordOrchestrator: user not found email={}", email);
                    return new UserNotFoundException(
                            "User not found with email: " + email
                    );
                });

        // 2️⃣ Create reset token
        String token = verificationService.createVerificationToken(
                user,
                "PASSWORD_RESET"
        );

        CompletableFuture<Boolean> emailResultFuture = new CompletableFuture<>();

        afterCommitExecutor.run(() -> {
            // This runs after DB commit
            emailService.sendSetPasswordEmail(user.getEmail(), token)
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

        log.info("ForgotPasswordOrchestrator: reset link sent email={}. Email sent={}", email, emailSent);

        return ForgotPasswordResult.builder()
                .outcome(AuthOutcome.PASSWORD_RESET)
                .email(email)
                .emailSent(emailSent)
                .build();
    }
}


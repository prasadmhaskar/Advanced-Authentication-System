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

import java.util.Optional;
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
        log.info("ForgotPasswordOrchestrator: request for email={}", email);

        // 1️⃣ Validate user existence (Privacy-First)
        Optional<User> userOpt = userRepository.findByEmail(email);

        if (userOpt.isEmpty()) {
            // Log it internally for security monitoring
            log.warn("ForgotPasswordOrchestrator: email not found={}", email);

            // Return a successful response to the API consumer
            return ForgotPasswordResult.builder()
                    .outcome(AuthOutcome.PASSWORD_RESET)
                    .emailSent(true) // Lie to the client to prevent enumeration
                    .message("If an account exists, a reset link has been sent.")
                    .build();
        }

        User user = userOpt.get();

        // 2️⃣ Create reset token (Standard flow)
        String token = verificationService.createVerificationToken(user, "PASSWORD_RESET");

        CompletableFuture<Boolean> emailResultFuture = new CompletableFuture<>();

        afterCommitExecutor.run(() -> {
            emailService.sendSetPasswordEmail(user.getEmail(), token)
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

        log.info("ForgotPasswordOrchestrator: reset link sent email={}. Email sent={}", email, emailSent);

        return ForgotPasswordResult.builder()
                .outcome(AuthOutcome.PASSWORD_RESET)
                .email(email)
                .emailSent(emailSent)
                .build();
    }
}


package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.result.ForgotPasswordResult;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.service.email.EmailService;
import com.pnm.auth.service.auth.VerificationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

@Service
@RequiredArgsConstructor
@Slf4j
public class ForgotPasswordOrchestratorImpl implements ForgotPasswordOrchestrator {

    private final UserRepository userRepository;
    private final VerificationService verificationService;
    private final EmailService emailService;

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

        // 3️⃣ Send Email Directly
        CompletableFuture<Boolean> emailResultFuture = emailService.sendSetPasswordEmail(user.getEmail(), token);

        boolean emailSent;
        try {
            emailSent = emailResultFuture.get(1000, TimeUnit.MILLISECONDS);

        } catch (TimeoutException e) {
            log.warn("ForgotPasswordOrchestrator: Email timed out. User will receive it eventually.");
            emailSent = false;

        } catch (ExecutionException e) {
            log.error("ForgotPasswordOrchestrator: CRITICAL EMAIL FAILURE. Cause: {}", e.getCause().getMessage());
            emailSent = false;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
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


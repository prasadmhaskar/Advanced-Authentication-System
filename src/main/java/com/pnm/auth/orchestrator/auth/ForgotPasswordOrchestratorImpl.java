package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.result.ForgotPasswordResult;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.service.email.EmailService;
import com.pnm.auth.service.auth.VerificationService;
import com.pnm.auth.web.context.RequestContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.security.SecureRandom;
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

    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    public ForgotPasswordResult requestReset(String rawEmail) {

        String email = rawEmail.trim().toLowerCase();

        log.info("ForgotPasswordOrchestrator: started for email={}", email);

        // Load user
        Optional<User> userOpt = userRepository.findByEmail(email);

        if (userOpt.isEmpty()) {
            log.warn("ForgotPasswordOrchestrator: account not found with email={}", email);

            try { Thread.sleep(secureRandom.nextInt(200) + 300); } catch (InterruptedException ignored) {}

            // Return a fake successful response - in case if attacker is trying to find out email is registered or not.
            return ForgotPasswordResult.builder()
                    .outcome(AuthOutcome.PASSWORD_RESET)
                    .message("If your email is registered, password reset link has been dispatched to your email address.")
                    .build();
        }

        User user = userOpt.get();

        // Create reset token
        String token = verificationService.createVerificationToken(user, "PASSWORD_RESET");

        // Send email
        emailService.sendSetPasswordEmail(user.getEmail(), token);

        log.info("ForgotPasswordOrchestrator: finished for email={}", email);

        return ForgotPasswordResult.builder()
                .outcome(AuthOutcome.PASSWORD_RESET)
                .email(email)
                .build();
    }
}


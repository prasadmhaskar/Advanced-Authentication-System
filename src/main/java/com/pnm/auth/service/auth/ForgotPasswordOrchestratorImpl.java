package com.pnm.auth.service.auth;

import com.pnm.auth.dto.result.ForgotPasswordResult;
import com.pnm.auth.entity.User;
import com.pnm.auth.enums.AuditAction;
import com.pnm.auth.enums.AuthOutcome;
import com.pnm.auth.exception.EmailSendFailedException;
import com.pnm.auth.exception.UserNotFoundException;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.service.EmailService;
import com.pnm.auth.service.VerificationService;
import com.pnm.auth.util.Audit;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class ForgotPasswordOrchestratorImpl implements ForgotPasswordOrchestrator {

    private final UserRepository userRepository;
    private final VerificationService verificationService;
    private final EmailService emailService;

    @Override
    @Audit(action = AuditAction.PASSWORD_RESET_REQUEST,
            description = "Forgot password request")
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

        // 3️⃣ Send reset email
        try {
            emailService.sendPasswordResetEmail(email, token);
        } catch (EmailSendFailedException ex) {
            log.error("ForgotPasswordOrchestrator: email send failed email={}", email);
            throw ex;
        }

        log.info("ForgotPasswordOrchestrator: reset link sent email={}", email);

        return ForgotPasswordResult.builder()
                .outcome(AuthOutcome.PASSWORD_RESET)
                .message("Password reset link sent to email")
                .email(email)
                .build();
    }
}


package com.pnm.auth.service;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthProviderType;
import com.pnm.auth.exception.custom.UserNotFoundException;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.service.auth.VerificationService;
import com.pnm.auth.service.email.EmailService;
import com.pnm.auth.util.AfterCommitExecutor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class PasswordSetupService {

    private final UserRepository userRepository;
    private final VerificationService verificationService;
    private final EmailService emailService;
    private final AfterCommitExecutor afterCommitExecutor;

    @Transactional
    public void sendSetupEmail(String email) {

        User user = userRepository.findByEmail(email.trim().toLowerCase())
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (!user.hasProvider(AuthProviderType.EMAIL)) {
            throw new IllegalStateException("EMAIL provider not linked");
        }

        if (user.getPassword() != null) {
            log.warn("Password already set email={}", email);
            return; // idempotent
        }

        String token = verificationService.createVerificationToken(
                user,
                "PASSWORD_RESET"
        );

        afterCommitExecutor.run(() ->
                emailService.sendSetPasswordEmail(user.getEmail(), token)
        );

        log.info("Password setup email sent email={}", email);
    }
}


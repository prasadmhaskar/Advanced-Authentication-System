package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.request.RegisterRequest;
import com.pnm.auth.dto.result.RegistrationResult;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.domain.enums.AuthProviderType;
import com.pnm.auth.exception.custom.EmailSendFailedException;
import com.pnm.auth.exception.custom.UserAlreadyExistsException;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.service.email.EmailService;
import com.pnm.auth.service.auth.VerificationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class RegisterOrchestratorImpl implements RegisterOrchestrator {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final VerificationService verificationService;
    private final EmailService emailService;

    @Override
    @Transactional
    public RegistrationResult register(RegisterRequest request) {

        String email = request.getEmail().trim().toLowerCase();
        log.info("RegisterOrchestrator: started email={}", email);

        // 1️⃣ Email already exists?
        if (userRepository.findByEmail(email).isPresent()) {
            log.warn("RegisterOrchestrator: email already exists email={}", email);
            throw new UserAlreadyExistsException(
                    "The email " + email + " is already registered"
            );
        }

        // 2️⃣ Create user
        User user = new User();
        user.setFullName(request.getFullName());
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRoles(List.of("ROLE_USER"));
        user.setAuthProviderType(AuthProviderType.EMAIL);

        userRepository.save(user);

        // 3️⃣ Create verification token
        String token = verificationService.createVerificationToken(
                user,
                "EMAIL_VERIFICATION"
        );

        // 4️⃣ Send verification email
        try {
            emailService.sendVerificationEmail(email, token);
        } catch (EmailSendFailedException ex) {
            // already meaningful → just log and bubble
            log.error("RegisterOrchestrator: verification email failed email={}", email);
            throw ex;
        }

        log.info("RegisterOrchestrator: registration completed email={}", email);

        return RegistrationResult.builder()
                .outcome(AuthOutcome.REGISTERED)
                .message("Registration successful. Please verify your email.")
                .email(email)
                .build();
    }
}


package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.domain.entity.UserOAuthProvider;
import com.pnm.auth.domain.enums.NextAction;
import com.pnm.auth.dto.request.RegisterRequest;
import com.pnm.auth.dto.result.RegistrationResult;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.domain.enums.AuthProviderType;
import com.pnm.auth.exception.custom.EmailSendFailedException;
import com.pnm.auth.exception.custom.UserAlreadyExistsException;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.security.oauth.AccountLinkTokenService;
import com.pnm.auth.service.email.EmailService;
import com.pnm.auth.service.auth.VerificationService;
import com.pnm.auth.util.AfterCommitExecutor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class RegisterOrchestratorImpl implements RegisterOrchestrator {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final VerificationService verificationService;
    private final EmailService emailService;
    private final AccountLinkTokenService accountLinkTokenService;
    private final AfterCommitExecutor afterCommitExecutor;

    @Override
    @Transactional
    public RegistrationResult register(RegisterRequest request) {

        String email = request.getEmail().trim().toLowerCase();
        log.info("RegisterOrchestrator: started email={}", email);

        // Check if user exists
        Optional<User> optionalUser = userRepository.findByEmail(email);

        if (optionalUser.isPresent()) {

            User existingUser = optionalUser.get();

            // EMAIL already linked → normal duplicate case
            if (existingUser.hasProvider(AuthProviderType.EMAIL)) {
                log.warn("RegisterOrchestrator: email already registered with EMAIL email={}", email);
                throw new UserAlreadyExistsException(
                        "The email " + email + " is already registered"
                );
            }

            // OAuth exists but EMAIL not linked → LINK REQUIRED
            AuthProviderType existingProvider =
                    existingUser.getAuthProviders().stream()
                            .map(UserOAuthProvider::getProviderType)
                            .filter(p -> p != AuthProviderType.EMAIL)
                            .findFirst()
                            .orElseThrow(() -> new IllegalStateException(
                                    "OAuth provider expected but not found"
                            ));

            // ⭐ CREATE LINK TOKEN
            String linkToken = accountLinkTokenService.createLinkToken(
                    existingUser,
                    AuthProviderType.EMAIL,
                    email
            );

            log.warn("RegisterOrchestrator: email exists with OAuth provider={} email={}", existingProvider, email);

            return RegistrationResult.builder()
                    .outcome(AuthOutcome.LINK_REQUIRED)
                    .email(email)
                    .existingProvider(existingProvider)
                    .attemptedProvider(AuthProviderType.EMAIL)
                    .nextAction(NextAction.LINK_ACCOUNT)
                    .linkToken(linkToken)
                    .build();
        }

        // Create new EMAIL user
        User user = new User();
        user.setFullName(request.getFullName());
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRoles(List.of("ROLE_USER"));

        // Add EMAIL auth provider
        user.linkProvider(AuthProviderType.EMAIL, email);

        userRepository.save(user);

        // Create verification token
        String token = verificationService.createVerificationToken(
                user,
                "EMAIL_VERIFICATION"
        );

        // Send verification email
            afterCommitExecutor.run(() ->
                    emailService.sendVerificationEmail(email, token));

        log.info("RegisterOrchestrator: registration completed email={}", email);

        return RegistrationResult.builder()
                .outcome(AuthOutcome.REGISTERED)
                .email(email)
                .nextAction(NextAction.VERIFY_EMAIL)
                .build();
    }
}



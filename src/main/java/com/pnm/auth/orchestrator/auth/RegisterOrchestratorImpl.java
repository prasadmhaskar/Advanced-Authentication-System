package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.domain.entity.UserOAuthProvider;
import com.pnm.auth.domain.enums.NextAction;
import com.pnm.auth.dto.request.RegisterRequest;
import com.pnm.auth.dto.result.RegistrationResult;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.domain.enums.AuthProviderType;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.security.oauth.AccountLinkTokenService;
import com.pnm.auth.service.auth.UserPersistenceService;
import com.pnm.auth.service.email.EmailService;
import com.pnm.auth.service.impl.auth.UserPersistenceServiceImpl;
import com.pnm.auth.service.ipmonitoring.IpMonitoringService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

//@Service
//@RequiredArgsConstructor
//@Slf4j
//public class RegisterOrchestratorImpl implements RegisterOrchestrator {
//
//    private final UserRepository userRepository;
//    private final EmailService emailService;
//    private final AccountLinkTokenService accountLinkTokenService;
//    private final UserPersistenceService userPersistenceService;
//
//    @Override
//    public RegistrationResult register(RegisterRequest request) {
//
//        String email = request.getEmail().trim().toLowerCase();
//        log.info("RegisterOrchestrator: started email={}", email);
//
//        // Check if user exists
//        Optional<User> optionalUser = userRepository.findByEmail(email);
//
//        if (optionalUser.isPresent()) {
//
//            User existingUser = optionalUser.get();
//
//            // EMAIL already linked -> normal duplicate case
//            if (existingUser.hasProvider(AuthProviderType.EMAIL)) {
//                log.warn("RegisterOrchestrator: email already registered with EMAIL email={}", email);
//                throw new UserAlreadyExistsException(
//                        "The email " + email + " is already registered"
//                );
//            }
//
//            // OAuth exists but EMAIL not linked -> LINK REQUIRED
//            AuthProviderType existingProvider =
//                    existingUser.getAuthProviders().stream()
//                            .map(UserOAuthProvider::getProviderType)
//                            .filter(p -> p != AuthProviderType.EMAIL)
//                            .findFirst()
//                            .orElseThrow(() -> new IllegalStateException(
//                                    "OAuth provider expected but not found"
//                            ));
//
//
//
//            // ⭐ CREATE LINK TOKEN
//            String linkToken = accountLinkTokenService.createLinkToken(
//                    existingUser,
//                    AuthProviderType.EMAIL,
//                    email
//            );
//
//            log.warn("RegisterOrchestrator: email exists with OAuth provider={} email={}", existingProvider, email);
//
//            return RegistrationResult.builder()
//                    .outcome(AuthOutcome.LINK_REQUIRED)
//                    .email(email)
//                    .existingProvider(existingProvider)
//                    .attemptedProvider(AuthProviderType.EMAIL)
//                    .nextAction(NextAction.LINK_ACCOUNT)
//                    .linkToken(linkToken)
//                    .build();
//        }
//
//        // Create new EMAIL user
//        // 1. Perform DB work (Transaction starts and ends here)
//        String token = userPersistenceService.saveUserAndCreateToken(request);
//
//// We use a manual future to bridge the transaction boundary
//        CompletableFuture<Boolean> emailResultFuture = emailService.sendVerificationEmail(email, token);
//
//// Now we wait for the email result (with a timeout so we don't hang the API)
//        boolean emailSent;
//        try {
//            // 2 seconds is plenty for an async handoff/circuit breaker check
//            emailSent = emailResultFuture.get(5, TimeUnit.SECONDS);
//        } catch (Exception e) {
//            emailSent = false;
//        }
//
//        log.info("RegisterOrchestrator: Verification email status email={} sent={}", email, emailSent);
//
//        return RegistrationResult.builder()
//                .outcome(AuthOutcome.REGISTERED)
//                .email(email)
//                .emailSent(emailSent) // 👈 Pass this to the controller
//                .nextAction(NextAction.VERIFY_EMAIL)
//                .build();
//    }
//}

@Service
@RequiredArgsConstructor
@Slf4j
public class RegisterOrchestratorImpl implements RegisterOrchestrator {

    private final UserRepository userRepository;
    private final EmailService emailService;
    private final AccountLinkTokenService accountLinkTokenService;
    private final UserPersistenceService userPersistenceService;
    private final IpMonitoringService ipMonitoringService;

    @Override
    public RegistrationResult register(RegisterRequest request, String ip, String ua) {

        String email = request.getEmail().trim().toLowerCase();
        log.info("RegisterOrchestrator: started for email={}", email);

        // 1️⃣ PREVENTATIVE CHECK (Read-Only)
        // If they are over limit, we throw exception HERE.
        ipMonitoringService.checkRegistrationEligibility(ip, ua);

        // 1️⃣ Check if user exists (Privacy-First Handling)
        Optional<User> optionalUser = userRepository.findByEmail(email);

        if (optionalUser.isPresent()) {

            User existingUser = optionalUser.get();

            // A) EMAIL provider exists -> FAKE SUCCESS (Prevent Enumeration)
            if (existingUser.hasProvider(AuthProviderType.EMAIL)) {
                log.warn("RegisterOrchestrator: Duplicate registration attempt for email={}. Returning fake success.", email);

                // Return "Fake" Success to baffle attackers
                return RegistrationResult.builder()
                        .outcome(AuthOutcome.REGISTERED)
                        .email(email)
                        .emailSent(true) // Lie to maintain illusion
                        .nextAction(NextAction.VERIFY_EMAIL)
                        .build();
            }

            // B) OAuth exists but EMAIL not linked -> LINK REQUIRED
            // Note: This technically leaks that an OAuth account exists,
            // but is required for the "Link Account" flow.
            AuthProviderType existingProvider =
                    existingUser.getAuthProviders().stream()
                            .map(UserOAuthProvider::getProviderType)
                            .filter(p -> p != AuthProviderType.EMAIL)
                            .findFirst()
                            .orElseThrow(() -> new IllegalStateException("OAuth provider expected"));

            // Create Link Token (Transactional inside service)
            String linkToken = accountLinkTokenService.createLinkToken(existingUser, AuthProviderType.EMAIL, email);

            log.info("RegisterOrchestrator: Account link required for email={}", email);

            return RegistrationResult.builder()
                    .outcome(AuthOutcome.LINK_REQUIRED)
                    .email(email)
                    .existingProvider(existingProvider)
                    .attemptedProvider(AuthProviderType.EMAIL)
                    .nextAction(NextAction.LINK_ACCOUNT)
                    .linkToken(linkToken)
                    .build();
        }

        // 2️⃣ Create new EMAIL user
        // DB Transaction happens inside this service call
        UserPersistenceServiceImpl.UserCreationResult result = userPersistenceService.saveUserAndCreateToken(request);

        try {
            ipMonitoringService.recordRegistrationSuccess(result.user().getId(), ip, ua);
        } catch (Exception e) {
            // Don't fail the registration just because logging failed, but alert admin
            log.error("Failed to log IP for new user={}", email, e);
        }

        // 3️⃣ Send Verification Email (Async Bridge)
        CompletableFuture<Boolean> emailResultFuture = emailService.sendVerificationEmail(email, result.token());

        boolean emailSent;
        try {
            // Wait budget: 1000ms
            emailSent = emailResultFuture.get(1000, TimeUnit.MILLISECONDS);

        } catch (TimeoutException e) {
            // 🟡 CASE 1: Server is slow.
            // This is "Normal" in distributed systems. Don't wake up the dev team.
            log.warn("RegisterOrchestrator: Email timed out. User will receive it eventually.");
            emailSent = false;

        } catch (ExecutionException e) {
            // 🔴 CASE 2: System is BROKEN.
            // (Wrong password, DNS failure, Port blocked).
            // Log this as ERROR so your monitoring system detects it immediately.
            log.error("RegisterOrchestrator: CRITICAL EMAIL FAILURE. Cause: {}", e.getCause().getMessage());

            // ☠️ STRATEGIC DECISION: Still let the user register.
            // It's better to have a user you can fix later than a rejected request.
            emailSent = false;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            emailSent = false;
        }

        log.info("RegisterOrchestrator: finished for email={}, emailSentWithInTime={}", email, emailSent);

        return RegistrationResult.builder()
                .outcome(AuthOutcome.REGISTERED)
                .email(email)
                .emailSent(emailSent)
                .nextAction(NextAction.VERIFY_EMAIL)
                .build();
    }
}



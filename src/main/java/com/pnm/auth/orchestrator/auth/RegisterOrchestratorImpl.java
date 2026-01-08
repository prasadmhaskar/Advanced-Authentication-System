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
import com.pnm.auth.web.context.RequestContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;



@Service
@RequiredArgsConstructor
@Slf4j
public class RegisterOrchestratorImpl implements RegisterOrchestrator {

    private final UserRepository userRepository;
    private final EmailService emailService;
    private final AccountLinkTokenService accountLinkTokenService;
    private final UserPersistenceService userPersistenceService;
    private final IpMonitoringService ipMonitoringService;

    @Value("${email.send.timeout.ms}")
    private long emailTimeout;

    @Override
    public RegistrationResult register(RegisterRequest request, RequestContext ctx) {

        String email = request.getEmail().trim().toLowerCase();
        String ip = ctx.ip();
        String ua = ctx.userAgent();

        log.info("RegisterOrchestrator: started ip={} and email={}",ctx.ip(), email);


        // Check for restricting multiple accounts registration per device
        //This is just a basic check code for restricting multiple users per device. We have kept limit to 20 because,
        // we have written basic UserAgentParser code. Hence, different clients can have same device signature.
        // In future we can replace this with frontEnd fingerprint library which generates unique hash for different users.
        ipMonitoringService.checkRegistrationEligibility(ip, ua);

        // Check if user exists
        Optional<User> optionalUser = userRepository.findByEmail(email);

        if (optionalUser.isPresent()) {

            User existingUser = optionalUser.get();

            // User already exists with providerType Email -> if login/register attempted by attacker to know this
            // email is already registered or not, returning fake success, hence he will not know that this email id is registered.
            if (existingUser.hasProvider(AuthProviderType.EMAIL)) {
                log.warn("RegisterOrchestrator: Duplicate registration attempt for email={}. Returning fake success.", email);

                // Return fake success
                return RegistrationResult.builder()
                        .outcome(AuthOutcome.REGISTERED)
                        .email(email)
                        .emailSent(true) // Lie to maintain illusion
                        .nextAction(NextAction.VERIFY_EMAIL)
                        .build();
            }

            // User already exists with providerType -> any OAuthProvider. We will give the option to link both
            // accounts so that after linking user can log in using both Google and email also.
            AuthProviderType existingProvider =
                    existingUser.getAuthProviders().stream()
                            .map(UserOAuthProvider::getProviderType)
                            .filter(p -> p != AuthProviderType.EMAIL)
                            .findFirst()
                            .orElseThrow(() -> new IllegalStateException("OAuth provider expected"));

            // Create Link Token
            String linkToken = accountLinkTokenService.createLinkToken(existingUser, AuthProviderType.EMAIL, email, false);

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

        // Create new user
        UserPersistenceServiceImpl.UserCreationResult result = userPersistenceService.saveUserAndCreateToken(request);

        try {
            ipMonitoringService.recordRegistrationSuccess(result.user().getId(), ip, ua);
        } catch (Exception e) {
            log.error("Failed to log IP for new user={}", email, e);
        }

        // Send Verification Email (Async Bridge)
        CompletableFuture<Boolean> emailResultFuture = emailService.sendVerificationEmail(email, result.token());

        boolean emailSent;
        try {
            // for checking email is sent within 1000 ms or not based on that, we will return proper response
            // to user. Also, we will know that email server is delayed or not.
            emailSent = emailResultFuture.get(emailTimeout, TimeUnit.MILLISECONDS);

        } catch (TimeoutException e) {
            // case 1: Server is slow.
            // This is normal in distributed systems, don't wake up the dev team.
            log.warn("RegisterOrchestrator: Email timed out. User will receive it eventually.");
            emailSent = false;

        } catch (ExecutionException e) {
            // case 2: System is broken.
            // (Wrong password, DNS failure, Port blocked) Log this as ERROR so your monitoring system detects it immediately.
            // Still let the user register. It's better to have a user you can fix later than a rejected request.
            log.error("RegisterOrchestrator: CRITICAL EMAIL FAILURE. Cause: {}", e.getCause().getMessage());
            emailSent = false;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            emailSent = false;
        }

        log.info("RegisterOrchestrator: finished ip={} and email={}",ctx.ip(), email);

        return RegistrationResult.builder()
                .outcome(AuthOutcome.REGISTERED)
                .email(email)
                .emailSent(emailSent)
                .nextAction(NextAction.VERIFY_EMAIL)
                .build();
    }
}



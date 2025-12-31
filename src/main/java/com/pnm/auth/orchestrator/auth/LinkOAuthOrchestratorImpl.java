package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.domain.enums.NextAction;
import com.pnm.auth.dto.request.LinkOAuthRequest;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuditAction;
import com.pnm.auth.dto.result.AccountLinkResult;
import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.dto.result.LinkingResult;
import com.pnm.auth.service.auth.AccountLinkingService;
import com.pnm.auth.service.email.EmailService;
import com.pnm.auth.util.Audit;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

//@Service
//@RequiredArgsConstructor
//@Slf4j
//public class LinkOAuthOrchestratorImpl implements LinkOAuthOrchestrator {
//
//    private final AccountLinkTokenRepository accountLinkTokenRepository;
//    private final UserOAuthProviderRepository providerRepository;
//    private final TokenService tokenService;
//    private final VerificationService verificationService;
//    private final AfterCommitExecutor afterCommitExecutor;
//    private final EmailService emailService;
//
//    @Override
//    @Transactional
//    @Audit(action = AuditAction.OAUTH_LINK, description = "Link OAuth account")
//    public AccountLinkResult link(LinkOAuthRequest request) {
//
//        log.info("LinkOAuthOrchestrator: started provider={}", request.getProvider());
//
//        // 1️⃣ Load & validate link token
//        AccountLinkToken linkToken = accountLinkTokenRepository
//                .findByToken(request.getLinkToken())
//                .orElseThrow(() -> new InvalidTokenException("Invalid link token"));
//
//        if (linkToken.getExpiresAt().isBefore(LocalDateTime.now())) {
//            accountLinkTokenRepository.delete(linkToken);
//            throw new InvalidTokenException("Link token expired");
//        }
//
//        // 2️⃣ Validate provider matches token
//        if (linkToken.getProviderToLink() != request.getProvider()) {
//            log.warn("LinkOAuthOrchestrator: provider mismatch tokenProvider={} requestProvider={}", linkToken.getProviderToLink(), request.getProvider());
//            throw new InvalidTokenException("Invalid provider for link token");
//        }
//
//        User user = linkToken.getUser();
//
//        // 3️⃣ Validate user state
//        if (!user.isActive()) {
//            log.warn("LinkOAuthOrchestrator: blocked user attempted linking email={}", user.getEmail());
//            throw new AccountBlockedException("Your account has been blocked.");
//        }
//
//        // 4️⃣ Idempotency: already linked
//        if (user.hasProvider(request.getProvider())) {
//            log.info(
//                    "LinkOAuthOrchestrator: provider already linked email={} provider={}",
//                    user.getEmail(),
//                    request.getProvider()
//            );
//            accountLinkTokenRepository.delete(linkToken);
//        }
//
//        // 5️⃣ Attach OAuth provider
//        UserOAuthProvider provider = UserOAuthProvider.builder()
//                .providerType(linkToken.getProviderToLink())
//                .providerId(linkToken.getProviderUserId())
//                .linkedAt(LocalDateTime.now())
//                .active(true)
//                .user(user)
//                .build();
//
//        providerRepository.save(provider);
//
//        // 6️⃣ Consume token (one-time use)
//        accountLinkTokenRepository.delete(linkToken);
//
//        //  Generate tokens (AUTO LOGIN)
//        AuthenticationResult auth = tokenService.generateTokens(user);
//
//        boolean passwordSetupRequired = false;
//        NextAction nextAction = NextAction.LOGIN;
//        String message1 = "Account linked and logged in successfully.";
//
//        // 7️⃣ Password setup (only if EMAIL added & password missing)
//        if (request.getProvider() == AuthProviderType.EMAIL && user.getPassword() == null) {
//            String token = verificationService.createVerificationToken(user, "PASSWORD_RESET");
//            CompletableFuture<Boolean> emailResultFuture = new CompletableFuture<>();
//
//            afterCommitExecutor.run(() -> {
//                emailService.sendSetPasswordEmail(user.getEmail(), token)
//                        .thenAccept(emailResultFuture::complete)
//                        .exceptionally(ex -> {
//                            emailResultFuture.complete(false);
//                            return null;
//                        });
//            });
//            boolean emailSent = true;
//            try {
//                // 2 seconds is plenty for an async handoff/circuit breaker check
//                emailSent = emailResultFuture.get(2, TimeUnit.SECONDS);
//            } catch (Exception e) {
//                emailSent = false;
//            }
//            passwordSetupRequired = true;
//            nextAction = NextAction.RESET_PASSWORD;
//            String message2 = "Account linked. Please set a password to enable email login.";
//
//            log.info("LinkOAuthOrchestrator: Account linked for email={}, provider={}, emailSent={}", user.getEmail(), request.getProvider(), emailSent);
//
//            return AccountLinkResult.builder()
//                    .outcome(AuthOutcome.SUCCESS)
//                    .email(user.getEmail())
//                    .accessToken(auth.getAccessToken())
//                    .refreshToken(auth.getRefreshToken())
//                    .passwordSetupRequired(passwordSetupRequired)
//                    .nextAction(nextAction)
//                    .emailSent(emailSent)
//                    .message(message2)
//                    .build();
//        }
//
//        log.info("LinkOAuthOrchestrator: completed email={} provider={}",
//                user.getEmail(), request.getProvider());
//
//        return AccountLinkResult.builder()
//                .outcome(AuthOutcome.SUCCESS)
//                .email(user.getEmail())
//                .accessToken(auth.getAccessToken())
//                .refreshToken(auth.getRefreshToken())
//                .passwordSetupRequired(passwordSetupRequired)
//                .emailSent(true)
//                .nextAction(nextAction)
//                .message(message1)
//                .build();
//    }
//}


@Service
@RequiredArgsConstructor
@Slf4j
public class LinkOAuthOrchestratorImpl implements LinkOAuthOrchestrator {

    private final AccountLinkingService accountLinkingService; // 👈 Inject new service
    private final EmailService emailService;

    @Override
    @Audit(action = AuditAction.OAUTH_LINK, description = "Link OAuth account")
    public AccountLinkResult link(LinkOAuthRequest request) {

        log.info("LinkOAuthOrchestrator: started provider={}", request.getProvider());

        // 1. Execute DB Logic (Transaction opens and closes inside this call)
        LinkingResult internalResult = accountLinkingService.linkAccount(request);

        User user = internalResult.getUser();
        AuthenticationResult auth = internalResult.getAuthTokens();
        String resetToken = internalResult.getPasswordResetToken();

        boolean passwordSetupRequired = false;
        NextAction nextAction = NextAction.LOGIN;
        String message = "Account linked and logged in successfully.";
        boolean emailSent = true;

        // 2. Handle Email (Outside Transaction)
        if (resetToken != null) {
            passwordSetupRequired = true;
            nextAction = NextAction.RESET_PASSWORD;

            // Send Email immediately
            CompletableFuture<Boolean> emailResultFuture = emailService.sendSetPasswordEmail(user.getEmail(), resetToken);

            try {
                emailSent = emailResultFuture.get(1000, TimeUnit.MILLISECONDS);

            } catch (TimeoutException e) {
                log.warn("LinkOAuthOrchestrator: Email timed out. User will receive it eventually.");
                emailSent = false;

            } catch (ExecutionException e) {
                log.error("LinkOAuthOrchestrator: CRITICAL EMAIL FAILURE. Cause: {}", e.getCause().getMessage());
                emailSent = false;

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                emailSent = false;
            }
        }

        log.info("LinkOAuthOrchestrator: completed email={} provider={} emailSent={}",
                user.getEmail(), request.getProvider(), emailSent);

        String msg = emailSent ?
                "Account linked, please set a password to enable email login. Link email for setting password is sent successfully"
                :"Account linked, please set a password to enable email login. Link email for setting password is on its way";


        return AccountLinkResult.builder()
                .outcome(AuthOutcome.SUCCESS)
                .email(user.getEmail())
                .accessToken(auth.getAccessToken())
                .refreshToken(auth.getRefreshToken())
                .passwordSetupRequired(passwordSetupRequired)
                .nextAction(nextAction)
                .emailSent(emailSent)
                .message(msg)
                .build();
    }
}

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

        String msg;
        if (passwordSetupRequired){
            msg = emailSent ?
                    "Account linked, please set a password to enable email login. Link email for setting password is sent successfully"
                    :"Account linked, please set a password to enable email login. Link email for setting password is on its way";
        }
        else {
            msg = "Account linked successfully";
        }

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

package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.domain.entity.AccountLinkToken;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.domain.enums.NextAction;
import com.pnm.auth.dto.request.LinkOAuthRequest;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuditAction;
import com.pnm.auth.dto.result.AccountLinkResult;
import com.pnm.auth.dto.result.LinkingResult;
import com.pnm.auth.security.oauth.AccountLinkTokenService;
import com.pnm.auth.service.auth.AccountLinkingService;
import com.pnm.auth.service.email.EmailService;
import com.pnm.auth.util.Audit;
import com.pnm.auth.web.context.RequestContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;


@Service
@RequiredArgsConstructor
@Slf4j
public class LinkOAuthOrchestratorImpl implements LinkOAuthOrchestrator {

    private final AccountLinkingService accountLinkingService;
    private final EmailService emailService;
    private final AccountLinkTokenService accountLinkTokenService;

    @Value("${email.send.timeout.ms}")
    private long emailTimeout;

    @Override
    @Audit(action = AuditAction.OAUTH_LINK, description = "Link OAuth account")
    public AccountLinkResult link(LinkOAuthRequest request, RequestContext ctx) {

        String ip = ctx.ip();

        log.info("LinkOAuthOrchestrator: started ip={} and provider={}",ip, request.getProvider());

        AccountLinkToken accountLinkToken = accountLinkTokenService.validate(request.getLinkToken());

        // Link account
        LinkingResult internalResult = accountLinkingService.linkAccount(request, ctx);

        String accessToken = null;
        String refreshToken = null;
        boolean passwordSetupRequired = internalResult.getPasswordResetToken() != null;

        // Decide: return tokens or return null? (If passwordSetup is required, we will not return tokens)
        if (accountLinkToken.isTrustedSource()){
            accessToken = internalResult.getAuthTokens().getAccessToken();
            refreshToken = internalResult.getAuthTokens().getRefreshToken();
        }

        User user = internalResult.getUser();
        String resetToken = internalResult.getPasswordResetToken();

        NextAction nextAction = NextAction.LOGIN;
        boolean emailSent = true;

        // Password setup required, send email for setting password
        if (resetToken != null) {
            nextAction = NextAction.RESET_PASSWORD;

            // Send Email immediately
            CompletableFuture<Boolean> emailResultFuture = emailService.sendSetPasswordEmail(user.getEmail(), resetToken);

            try {
                emailSent = emailResultFuture.get(emailTimeout, TimeUnit.MILLISECONDS);

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

        log.info("LinkOAuthOrchestrator: finished ip={} email={} provider={} emailSentInTime={}",
                ip, user.getEmail(), request.getProvider(), emailSent);

        String msg;
        if (passwordSetupRequired){
            msg = emailSent ?
                    "Account linked, please set a password to enable email login. Email for setting password has been dispatched to your email address."
                    :"Account linked, please set a password to enable email login. Email for setting password is being processed and will arrive shortly to you email address.";
        }
        else {
            msg = "Account linked successfully";
        }

        return AccountLinkResult.builder()
                .outcome(AuthOutcome.SUCCESS)
                .email(user.getEmail())
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .passwordSetupRequired(passwordSetupRequired)
                .nextAction(nextAction)
                .emailSent(emailSent)
                .message(msg)
                .build();
    }
}

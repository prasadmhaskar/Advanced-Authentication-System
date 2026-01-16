package com.pnm.auth.orchestrator.auth.impl;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuditAction;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.domain.enums.NextAction;
import com.pnm.auth.dto.request.LinkOAuthRequest;
import com.pnm.auth.dto.result.AccountLinkResult;
import com.pnm.auth.dto.result.LinkingResult;
import com.pnm.auth.event.LoginSuccessEvent;
import com.pnm.auth.orchestrator.auth.LinkOAuthOrchestrator;
import com.pnm.auth.service.auth.AccountLinkingService;
import com.pnm.auth.util.Audit;
import com.pnm.auth.web.context.RequestContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class LinkOAuthOrchestratorImpl implements LinkOAuthOrchestrator {

    private final AccountLinkingService accountLinkingService;
    private final ApplicationEventPublisher eventPublisher;


    @Override
    @Audit(action = AuditAction.OAUTH_LINK, description = "Link OAuth account")
    public AccountLinkResult link(LinkOAuthRequest request, RequestContext ctx) {

        log.info("LinkOAuthOrchestrator: started for provider={}", request.getProvider());

        // Delegate business logic to Service
        LinkingResult internalResult = accountLinkingService.linkAccount(request, ctx);

        User user = internalResult.getUser();

        String accessToken = internalResult.getAuthTokens().getAccessToken();
        String refreshToken = internalResult.getAuthTokens().getRefreshToken();

        eventPublisher.publishEvent(new LoginSuccessEvent(user.getId(), user.getEmail(), ctx.ip(), ctx.userAgent()));

        log.info("LinkOAuthOrchestrator: finished for email={} and provider={}",
                user.getEmail(), request.getProvider());

        return AccountLinkResult.builder()
                .outcome(AuthOutcome.SUCCESS)
                .email(user.getEmail())
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .nextAction(NextAction.LOGIN)
                .message("Account linked successfully")
                .build();
    }
}
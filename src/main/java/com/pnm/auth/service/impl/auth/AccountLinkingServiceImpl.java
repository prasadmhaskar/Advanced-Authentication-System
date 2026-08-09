package com.pnm.auth.service.impl.auth;

import com.pnm.auth.domain.entity.AccountLinkToken;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.entity.UserOAuthProvider;
import com.pnm.auth.dto.request.LinkOAuthRequest;
import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.dto.result.LinkingResult;
import com.pnm.auth.event.FailureEvent;
import com.pnm.auth.exception.custom.AccountBlockedException;
import com.pnm.auth.exception.custom.HighRiskLoginException;
import com.pnm.auth.exception.custom.InvalidTokenException;
import com.pnm.auth.repository.AccountLinkTokenRepository;
import com.pnm.auth.repository.UserOAuthProviderRepository;
import com.pnm.auth.service.interfaces.auth.AccountLinkingService;
import com.pnm.auth.service.interfaces.auth.TokenService;
import com.pnm.auth.service.interfaces.login.ActivityService;
import com.pnm.auth.service.interfaces.risk.RiskEngineService;
import com.pnm.auth.web.context.RequestContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@Slf4j
@RequiredArgsConstructor
public class AccountLinkingServiceImpl implements AccountLinkingService {

    private final AccountLinkTokenRepository accountLinkTokenRepository;
    private final UserOAuthProviderRepository providerRepository;
    private final TokenService tokenService;
    private final RiskEngineService riskEngineService;
    private final ApplicationEventPublisher eventPublisher;

    @Value("${auth.risk.threshold.high}")
    private int highRiskScore;

    @Override
    @Transactional
    public LinkingResult linkAccount(LinkOAuthRequest request, RequestContext ctx) {
        // Load Token
        AccountLinkToken linkToken = accountLinkTokenRepository
                .findByToken(request.getLinkToken())
                .orElseThrow(() -> new InvalidTokenException("Invalid or expired link token"));

        // Validate Expiry
        if (linkToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            accountLinkTokenRepository.delete(linkToken); // Cleanup expired token
            throw new InvalidTokenException("Link token has expired");
        }

        // Validate Provider Match
        if (linkToken.getProviderToLink() != request.getProvider()) {
            throw new InvalidTokenException("Token invalid for this provider");
        }

        User user = linkToken.getUser();

        if (!user.isActive()) {
            throw new AccountBlockedException("Your account has been blocked.");
        }

        String ip = ctx.ip();
        String userAgent = ctx.userAgent();

        var risk = riskEngineService.evaluateRisk(user.getId(), ip, userAgent);

        if (risk.getScore() >= highRiskScore) {
            log.warn("AccountLinking: HIGH RISK link attempt blocked ip={}", ip);
            eventPublisher.publishEvent(new FailureEvent(user.getId(), user.getEmail(), ip, userAgent, "High risk link attempt"));
            // Burn token to prevent retry spam
            accountLinkTokenRepository.delete(linkToken);
            throw new HighRiskLoginException("Linking blocked due to high risk activity.");
        }

        // Idempotency: Only save if provider doesn't already exist
        // This handles cases where the user double-clicks the link button
        if (!user.hasProvider(request.getProvider())) {
            UserOAuthProvider provider = UserOAuthProvider.builder()
                    .providerType(linkToken.getProviderToLink())
                    .providerId(linkToken.getProviderUserId()) // Critical: Use ID from token, not request
                    .linkedAt(LocalDateTime.now())
                    .active(true)
                    .user(user)
                    .build();

            providerRepository.save(provider);
            log.info("AccountLinkingService: Linked provider={} to user={}", request.getProvider(), user.getId());
        }

        // Cleanup: Burn the token so it cannot be used again
        accountLinkTokenRepository.delete(linkToken);

        // Auto-Login: Generate JWTs immediately
        AuthenticationResult authTokens = tokenService.generateTokens(user, ctx);

        return LinkingResult.builder()
                .user(user)
                .authTokens(authTokens)
                .build();
    }
}
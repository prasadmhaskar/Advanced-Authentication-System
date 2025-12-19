package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.domain.entity.AccountLinkToken;
import com.pnm.auth.domain.entity.UserOAuthProvider;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.domain.enums.AuthProviderType;
import com.pnm.auth.domain.enums.NextAction;
import com.pnm.auth.dto.request.LinkOAuthRequest;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuditAction;
import com.pnm.auth.dto.result.AccountLinkResult;
import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.exception.custom.*;
import com.pnm.auth.repository.AccountLinkTokenRepository;
import com.pnm.auth.repository.UserOAuthProviderRepository;
import com.pnm.auth.service.PasswordSetupService;
import com.pnm.auth.service.auth.TokenService;
import com.pnm.auth.util.Audit;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class LinkOAuthOrchestratorImpl implements LinkOAuthOrchestrator {

    private final AccountLinkTokenRepository accountLinkTokenRepository;
    private final UserOAuthProviderRepository providerRepository;
    private final PasswordSetupService passwordSetupService;
    private final TokenService tokenService;

    @Override
    @Transactional
    @Audit(action = AuditAction.OAUTH_LINK, description = "Link OAuth account")
    public AccountLinkResult link(LinkOAuthRequest request) {

        log.info("LinkOAuthOrchestrator: started provider={}", request.getProvider());

        // 1️⃣ Load & validate link token
        AccountLinkToken linkToken = accountLinkTokenRepository
                .findByToken(request.getLinkToken())
                .orElseThrow(() -> new InvalidTokenException("Invalid link token"));

        if (linkToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            accountLinkTokenRepository.delete(linkToken);
            throw new InvalidTokenException("Link token expired");
        }

        // 2️⃣ Validate provider matches token
        if (linkToken.getProviderToLink() != request.getProvider()) {
            log.warn(
                    "LinkOAuthOrchestrator: provider mismatch tokenProvider={} requestProvider={}",
                    linkToken.getProviderToLink(),
                    request.getProvider()
            );
            throw new InvalidTokenException("Invalid provider for link token");
        }

        User user = linkToken.getUser();

        // 3️⃣ Validate user state
        if (!user.isActive()) {
            log.warn("LinkOAuthOrchestrator: blocked user attempted linking email={}", user.getEmail());
            throw new AccountBlockedException("Your account has been blocked.");
        }

        // 4️⃣ Idempotency: already linked
        if (user.hasProvider(request.getProvider())) {
            log.info(
                    "LinkOAuthOrchestrator: provider already linked email={} provider={}",
                    user.getEmail(),
                    request.getProvider()
            );
            accountLinkTokenRepository.delete(linkToken);
        }

        // 5️⃣ Attach OAuth provider
        UserOAuthProvider provider = UserOAuthProvider.builder()
                .providerType(linkToken.getProviderToLink())
                .providerId(linkToken.getProviderUserId())
                .linkedAt(LocalDateTime.now())
                .user(user)
                .build();

        providerRepository.save(provider);

        // 6️⃣ Consume token (one-time use)
        accountLinkTokenRepository.delete(linkToken);

        //  Generate tokens (AUTO LOGIN)
        AuthenticationResult auth = tokenService.generateTokens(user);

        boolean passwordSetupRequired = false;
        NextAction nextAction = NextAction.LOGIN;
        String message = "Account linked and logged in successfully.";

        // 7️⃣ Password setup (only if EMAIL added & password missing)
        if (request.getProvider() == AuthProviderType.EMAIL && user.getPassword() == null) {
            passwordSetupService.sendSetupEmail(user.getEmail());
            passwordSetupRequired = true;
            nextAction = NextAction.RESET_PASSWORD;
            message = "Account linked. Please set a password to enable email login.";
        }

        log.info("LinkOAuthOrchestrator: completed email={} provider={}",
                user.getEmail(), request.getProvider());

        return AccountLinkResult.builder()
                .outcome(AuthOutcome.SUCCESS)
                .email(user.getEmail())
                .accessToken(auth.getAccessToken())
                .refreshToken(auth.getRefreshToken())
                .passwordSetupRequired(passwordSetupRequired)
                .nextAction(nextAction)
                .message(message)
                .build();
    }
}

package com.pnm.auth.service.impl.auth;

import com.pnm.auth.domain.entity.AccountLinkToken;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.entity.UserOAuthProvider;
import com.pnm.auth.dto.request.LinkOAuthRequest;
import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.dto.result.LinkingResult;
import com.pnm.auth.exception.custom.AccountBlockedException;
import com.pnm.auth.exception.custom.InvalidTokenException;
import com.pnm.auth.repository.AccountLinkTokenRepository;
import com.pnm.auth.repository.UserOAuthProviderRepository;
import com.pnm.auth.service.auth.AccountLinkingService;
import com.pnm.auth.service.auth.TokenService;
import com.pnm.auth.web.context.RequestContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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

    @Override
    @Transactional
    public LinkingResult linkAccount(LinkOAuthRequest request, RequestContext ctx) {
        // 1. Load Token
        AccountLinkToken linkToken = accountLinkTokenRepository
                .findByToken(request.getLinkToken())
                .orElseThrow(() -> new InvalidTokenException("Invalid or expired link token"));

        // 2. Validate Expiry
        if (linkToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            accountLinkTokenRepository.delete(linkToken); // Cleanup expired token
            throw new InvalidTokenException("Link token has expired");
        }

        // 3. Validate Provider Match
        // Prevents using a token meant for Google to link a Facebook account
        if (linkToken.getProviderToLink() != request.getProvider()) {
            throw new InvalidTokenException("Token invalid for this provider");
        }

        User user = linkToken.getUser();

        if (!user.isActive()) {
            throw new AccountBlockedException("Your account has been blocked.");
        }

        // 4. Idempotency: Only save if provider doesn't already exist
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

        // 5. Cleanup: Burn the token so it cannot be used again
        accountLinkTokenRepository.delete(linkToken);

        // 6. Auto-Login: Generate JWTs immediately
        AuthenticationResult authTokens = tokenService.generateTokens(user, ctx);

        return LinkingResult.builder()
                .user(user)
                .authTokens(authTokens)
                .build();
    }
}
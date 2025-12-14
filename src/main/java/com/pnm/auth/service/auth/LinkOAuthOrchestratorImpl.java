package com.pnm.auth.service.auth;

import com.pnm.auth.dto.request.LinkOAuthRequest;
import com.pnm.auth.entity.User;
import com.pnm.auth.enums.AuditAction;
import com.pnm.auth.exception.*;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.security.JwtUtil;
import com.pnm.auth.util.Audit;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Caching;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class LinkOAuthOrchestratorImpl implements LinkOAuthOrchestrator {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;

    @Override
    @Transactional
    @Caching(evict = {
            @CacheEvict(value = "users", key = "#request.accessToken"),
            @CacheEvict(value = "users.list", allEntries = true)
    })
    @Audit(action = AuditAction.OAUTH_LINK, description = "Linking OAuth account")
    public void link(LinkOAuthRequest request) {

        log.info("LinkOAuthOrchestrator: started provider={}", request.getProviderType());

        // 1️⃣ Validate access token
        String accessToken = validateAccessToken(request.getAccessToken());

        // 2️⃣ Extract user identity
        String email = extractEmail(accessToken);

        // 3️⃣ Load and validate user
        User user = loadAndValidateUser(email);

        // 4️⃣ Validate provider compatibility
        validateProviderLink(user, request);

        // 5️⃣ Persist provider link
        persistProviderLink(user, request);

        log.info("LinkOAuthOrchestrator: completed successfully email={}", email);
    }

    // =====================================================
    // Helper methods
    // =====================================================

    private String validateAccessToken(String accessToken) {
        if (accessToken == null || accessToken.isBlank()) {
            log.warn("LinkOAuthOrchestrator: missing access token");
            throw new InvalidTokenException("Missing access token");
        }

        if (jwtUtil.isTokenExpired(accessToken)) {
            log.warn("LinkOAuthOrchestrator: token expired");
            throw new InvalidTokenException("Access token expired");
        }

        return accessToken;
    }

    private String extractEmail(String accessToken) {
        try {
            return jwtUtil.extractUsername(accessToken);
        } catch (Exception ex) {
            log.warn("LinkOAuthOrchestrator: failed to extract email msg={}", ex.getMessage());
            throw new InvalidTokenException("Invalid access token");
        }
    }

    private User loadAndValidateUser(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("LinkOAuthOrchestrator: user not found email={}", email);
                    return new UserNotFoundException("User not found");
                });

        if (!user.isActive()) {
            log.warn("LinkOAuthOrchestrator: blocked user attempted OAuth link email={}", email);
            throw new AccountBlockedException("Your account has been blocked.");
        }

        return user;
    }

    private void validateProviderLink(User user, LinkOAuthRequest request) {

        if (user.getAuthProviderType() != null &&
                !user.getAuthProviderType().equals(request.getProviderType())) {

            log.warn(
                    "LinkOAuthOrchestrator: provider conflict email={} existing={} new={}",
                    user.getEmail(),
                    user.getAuthProviderType(),
                    request.getProviderType()
            );

            throw new UserAlreadyExistsException(
                    "Account already linked with provider: " + user.getAuthProviderType()
            );
        }
    }

    private void persistProviderLink(User user, LinkOAuthRequest request) {
        try {
            user.setProviderId(request.getProviderId());
            user.setAuthProviderType(request.getProviderType());
            userRepository.save(user);

            log.info(
                    "LinkOAuthOrchestrator: provider linked email={} provider={}",
                    user.getEmail(),
                    request.getProviderType()
            );

        } catch (Exception ex) {
            log.error(
                    "LinkOAuthOrchestrator: failed to save provider link email={} msg={}",
                    user.getEmail(),
                    ex.getMessage(),
                    ex
            );

            throw new OAuthLinkFailedException(
                    "Failed to link OAuth provider. Please try again later."
            );
        }
    }
}

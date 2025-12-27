package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.domain.enums.AuditAction;
import com.pnm.auth.exception.custom.InvalidTokenException;
import com.pnm.auth.exception.custom.LogoutFailedException;
import com.pnm.auth.repository.RefreshTokenRepository;
import com.pnm.auth.util.JwtUtil;
import com.pnm.auth.util.Audit;
import com.pnm.auth.util.BlacklistedTokenStore;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Caching;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class LogoutOrchestratorImpl implements LogoutOrchestrator {

    private final JwtUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;
    private final BlacklistedTokenStore blacklistedTokenStore;

    @Override
    @Transactional
    @Caching(evict = {
            @CacheEvict(value = "users", key = "#accessToken"),
            @CacheEvict(value = "users.list", allEntries = true)
    })
    public void logout(String accessToken, String refreshToken) {

        log.info("LogoutOrchestrator: logout started");

        // 1️⃣ Validate access token presence
        if (accessToken == null || accessToken.isBlank()) {
            log.warn("LogoutOrchestrator: missing access token");
            throw new InvalidTokenException("Missing access token");
        }

        // 2️⃣ Blacklist access token
        blacklistAccessToken(accessToken);

        // 3️⃣ Delete refresh token (best effort but important)
        deleteRefreshToken(refreshToken);

        log.info("LogoutOrchestrator: logout completed");
    }

    // =====================================================
    // Helper methods
    // =====================================================

    private void blacklistAccessToken(String accessToken) {
        try {
            Claims claims = jwtUtil.extractAllClaims(accessToken);
            long expiryMillis = claims.getExpiration().getTime();

            blacklistedTokenStore.blacklistToken(accessToken, expiryMillis);

            log.info("LogoutOrchestrator: access token blacklisted until={}", expiryMillis);

        } catch (Exception ex) {
            log.error("LogoutOrchestrator: failed to blacklist access token msg={}",
                    ex.getMessage(), ex);
            throw new InvalidTokenException("Invalid access token");
        }
    }

    private void deleteRefreshToken(String refreshToken) {

        if (refreshToken == null || refreshToken.isBlank()) {
            log.warn("LogoutOrchestrator: refresh token missing, skipping deletion");
            return;
        }

        try {
            refreshTokenRepository.deleteByToken(refreshToken);
            log.info("LogoutOrchestrator: refresh token deleted");

        } catch (Exception ex) {
            log.error("LogoutOrchestrator: failed to delete refresh token msg={}",
                    ex.getMessage(), ex);
            throw new LogoutFailedException(
                    "Logout failed due to server error. Please try again."
            );
        }
    }
}


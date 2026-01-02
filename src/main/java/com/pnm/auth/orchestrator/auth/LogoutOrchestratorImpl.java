package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.domain.entity.RefreshToken;
import com.pnm.auth.domain.enums.AuditAction;
import com.pnm.auth.exception.custom.InvalidCredentialsException;
import com.pnm.auth.exception.custom.InvalidTokenException;
import com.pnm.auth.exception.custom.LogoutFailedException;
import com.pnm.auth.repository.RefreshTokenRepository;
import com.pnm.auth.repository.UserRepository;
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
    @Transactional // Rolls back DB (delete) if Redis fails, but not vice-versa
    public void logout(String accessToken, String refreshToken) {

        log.info("LogoutOrchestrator: logout started");

        // =========================================================
        // PHASE 1: VALIDATION (Read-Only)
        // Check everything BEFORE making any changes.
        // =========================================================

        // 1️⃣ Validate Access Token Structure & Extract Email
        if (accessToken == null || accessToken.isBlank()) {
            throw new InvalidTokenException("Missing access token");
        }

        String userEmail;
        long accessTokenExpiry;
        try {
            // This verifies signature and expiration without blacklisting yet
            Claims claims = jwtUtil.extractAllClaims(accessToken);
            userEmail = claims.getSubject();
            accessTokenExpiry = claims.getExpiration().getTime();
        } catch (Exception e) {
            throw new InvalidTokenException("Invalid access token");
        }

        // 2️⃣ Validate Refresh Token (If present)
        // We FIND it, but we do NOT delete it yet.
        RefreshToken storedRefreshToken = null;
        if (refreshToken != null && !refreshToken.isBlank()) {
            storedRefreshToken = refreshTokenRepository.findByToken(refreshToken)
                    .orElseThrow(() -> {
                        log.warn("Logout failed: Refresh token not found");
                        return new InvalidTokenException("Invalid refresh token");
                    });

            // Ownership Check
            if (!storedRefreshToken.getUser().getEmail().equals(userEmail)) {
                log.error("SECURITY: Token ownership mismatch user={} tokenOwner={}",
                        userEmail, storedRefreshToken.getUser().getEmail());
                throw new InvalidCredentialsException("Token ownership mismatch");
            }
        }

        // =========================================================
        // PHASE 2: EXECUTION (Destructive)
        // We only reach here if ALL tokens are valid.
        // =========================================================

        // 3️⃣ Delete Refresh Token (DB Transaction)
        if (storedRefreshToken != null) {
            refreshTokenRepository.delete(storedRefreshToken);
            log.info("LogoutOrchestrator: refresh token deleted");
        }

        // 4️⃣ Blacklist Access Token (Redis - Non-Transactional)
        // We do this LAST. If this fails, the DB transaction (Step 3) will rollback.
        try {
            blacklistedTokenStore.blacklistToken(accessToken, accessTokenExpiry);
            log.info("LogoutOrchestrator: access token blacklisted");
        } catch (Exception ex) {
            log.error("LogoutOrchestrator: Failed to write to Redis", ex);
            // Throwing exception here triggers @Transactional rollback for Step 3
            throw new LogoutFailedException("Logout failed due to system error");
        }

        log.info("LogoutOrchestrator: logout completed for email={}", userEmail);
    }
}


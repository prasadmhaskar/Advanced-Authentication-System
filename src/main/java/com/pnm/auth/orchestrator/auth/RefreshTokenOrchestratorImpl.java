package com.pnm.auth.orchestrator.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.domain.entity.RefreshToken;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuditAction;
import com.pnm.auth.exception.custom.InvalidCredentialsException;
import com.pnm.auth.exception.custom.InvalidTokenException;
import com.pnm.auth.exception.custom.TokenGenerationException;
import com.pnm.auth.repository.RefreshTokenRepository;
import com.pnm.auth.service.audit.AuditService;
import com.pnm.auth.service.login.LoginActivityService;
import com.pnm.auth.service.auth.TokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenOrchestratorImpl implements RefreshTokenOrchestrator {

    private final RefreshTokenRepository refreshTokenRepository;
    private final TokenService tokenService;
    private final LoginActivityService loginActivityService;
    private final AuditService auditService;

    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;

    @Override
    @Transactional
    public AuthenticationResult refresh(String rawToken, String ip, String userAgent) {

        String tokenPrefix = safeTokenPrefix(rawToken);
        log.info("RefreshTokenOrchestrator: started tokenPrefix={}", tokenPrefix);

        // 1️⃣ Load token metadata
        RefreshToken stored = refreshTokenRepository.findByToken(rawToken)
                .orElseThrow(() -> new InvalidTokenException("Invalid refresh token"));

        User user = stored.getUser();

        // 2️⃣ Expired / Invalidated check
        if (stored.isInvalidated() || stored.getExpiresAt().isBefore(LocalDateTime.now())) {
            log.warn("RefreshTokenOrchestrator: expired/invalidated token userId={}", user.getId());
            throw new InvalidTokenException("Refresh token expired");
        }

        // 3️⃣ Reuse Detection with Atomic Lock
        // We attempt to mark the token as 'used'.
        // If 'rowsUpdated' is 0, it means the token was ALREADY used (either historically or by a racing thread).
        int rowsUpdated = refreshTokenRepository.markAsUsed(rawToken);

        if (rowsUpdated == 0) {
            // 🚨 ALREADY USED: Handle Race Condition or Theft
            log.warn("RefreshTokenOrchestrator: Token already used (Race/Reuse) userId={}", user.getId());

            // A) Check Redis Grace Period (Handling Network Retries)
            String graceKey = "refresh_grace:" + rawToken;
            String cachedTokens = redisTemplate.opsForValue().get(graceKey);

            if (cachedTokens != null) {
                log.info("RefreshTokenOrchestrator: Grace period hit. Returning cached tokens.");
                try {
                    return objectMapper.readValue(cachedTokens, AuthenticationResult.class);
                } catch (Exception e) {
                    log.error("Failed to parse cached tokens", e);
                    // Proceed to treat as theft if parsing fails
                }
            }

            // B) No Grace Period -> Real Token Theft
            log.error("RefreshTokenOrchestrator: SECURITY ALERT - Token Reuse Detected! Nuking sessions for userId={}", user.getId());

            // Security: Invalidate ALL sessions for this user immediately
            refreshTokenRepository.invalidateAllForUser(user.getId());

            auditService.record(AuditAction.REFRESH_TOKEN_REUSE, user.getId(), user.getId(),
                    "Token reuse detected", null, null);

            throw new InvalidCredentialsException("Session compromised. Please login again.");
        }

        // 4️⃣ Rotate Token (We won the lock)
        try {
            // Generate new tokens (Session Capping logic handles the limit inside this service)
            AuthenticationResult result = tokenService.generateTokens(user);

            // ✅ SAVE TO REDIS (Grace Period: 60 Seconds)
            // If the client retries the old token within 60s, we return this result.
            String graceKey = "refresh_grace:" + rawToken;
            String jsonResult = objectMapper.writeValueAsString(result);

            redisTemplate.opsForValue().set(graceKey, jsonResult, 60, TimeUnit.SECONDS);

            // Log success (Best effort)
            try {
                loginActivityService.recordSuccess(user.getId(), user.getEmail(), ip, userAgent);
            } catch (Exception ignored) {
                // Do not fail the request if logging fails
            }

            return result;

        } catch (Exception ex) {
            log.error("RefreshTokenOrchestrator: rotation failed", ex);
            throw new TokenGenerationException("Unable to refresh token", ex);
        }
    }

    private String safeTokenPrefix(String token) {
        return token != null && token.length() > 8 ? token.substring(0, 8) : token;
    }
}
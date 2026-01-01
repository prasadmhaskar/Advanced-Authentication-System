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

        // 1️⃣ Load token
        RefreshToken stored = refreshTokenRepository.findByToken(rawToken)
                .orElseThrow(() -> new InvalidTokenException("Invalid refresh token"));

        User user = stored.getUser();

        // 2️⃣ Expired / invalidated
        if (stored.isInvalidated() || stored.getExpiresAt().isBefore(LocalDateTime.now())) {
            log.warn("RefreshTokenOrchestrator: expired token userId={}", user.getId());
            throw new InvalidTokenException("Refresh token expired");
        }

        // 3️⃣ Reuse detection with GRACE PERIOD (Redis)
        if (stored.isUsed()) {

            // ✅ CHECK REDIS: Is this a network retry?
            String graceKey = "refresh_grace:" + rawToken;
            String cachedTokens = redisTemplate.opsForValue().get(graceKey);

            if (cachedTokens != null) {
                log.info("RefreshTokenOrchestrator: Grace period hit. Returning cached tokens for userId={}", user.getId());
                try {
                    // Return the tokens we generated 1 second ago
                    return objectMapper.readValue(cachedTokens, AuthenticationResult.class);
                } catch (Exception e) {
                    log.error("Failed to parse cached tokens", e);
                }
            }

            // ❌ NO GRACE ENTRY FOUND: This is a real theft attempt!
            log.error("RefreshTokenOrchestrator: TOKEN REUSE DETECTED (No Grace Period) userId={}", user.getId());

            // Nuke ALL sessions for security
            refreshTokenRepository.invalidateAllForUser(user.getId());

            auditService.record(AuditAction.REFRESH_TOKEN_REUSE, user.getId(), user.getId(), "Token reuse detected", null, null);
            throw new InvalidCredentialsException("Session compromised. Please login again.");
        }

        // 4️⃣ Rotate token
        try {
            // Mark old token as used
            stored.setUsed(true);
            refreshTokenRepository.save(stored);

            // Generate new tokens (Cap logic happens inside here automatically)
            AuthenticationResult result = tokenService.generateTokens(user);

            // ✅ SAVE TO REDIS (Grace Period: 60 Seconds)
            // If the user retries with 'rawToken' within 60s, we return 'result' immediately.
            String graceKey = "refresh_grace:" + rawToken;
            String jsonResult = objectMapper.writeValueAsString(result);

            redisTemplate.opsForValue().set(graceKey, jsonResult, 60, TimeUnit.SECONDS);

            // Log success
            try {
                loginActivityService.recordSuccess(user.getId(), user.getEmail(), ip, userAgent);
            } catch (Exception ignored) {}

            return result;

        } catch (Exception ex) {
            log.error("RefreshTokenOrchestrator: rotation failed", ex);
            throw new TokenGenerationException("Unable to refresh token", ex);
        }
    }

    private String safeTokenPrefix(String token) {
        return token.length() > 8 ? token.substring(0, 8) : token;
    }
}


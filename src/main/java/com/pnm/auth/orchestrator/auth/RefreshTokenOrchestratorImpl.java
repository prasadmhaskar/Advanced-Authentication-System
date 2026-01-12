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
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.service.audit.AuditService;
import com.pnm.auth.service.login.LoginActivityService;
import com.pnm.auth.service.auth.TokenService;
import com.pnm.auth.util.UserAgentParser;
import com.pnm.auth.web.context.RequestContext;
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
    private final UserRepository userRepository;

    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;

    @Override
    @Transactional
    public AuthenticationResult refresh(String rawToken, RequestContext ctx) {

        String currentDeviceSignature = UserAgentParser
                .parse(ctx.userAgent())
                .getSignature();

        log.info("RefreshTokenOrchestrator: started");

        // Load token
        RefreshToken stored = refreshTokenRepository.findByToken(rawToken)
                .orElseThrow(() -> new InvalidTokenException("Invalid refresh token"));

        // Load user
        User user = stored.getUser();

        // Expired / Invalidated check
        if (stored.isInvalidated() || stored.getExpiresAt().isBefore(LocalDateTime.now())) {
            log.warn("RefreshTokenOrchestrator: expired/invalidated token userId={}", user.getId());
            throw new InvalidTokenException("Refresh token expired");
        }

        // Check current device signature is equal to the signature of the device for which this refresh token was provided.
        if (!stored.getDeviceSignature().equals(currentDeviceSignature)) {
            throw new InvalidTokenException("Refresh token used from different device");
        }


        // Reuse detection - we attempt to mark the token as used.
        // If rows updated is 0, it means the token was already used either historically or by a racing thread.
        int rowsUpdated = refreshTokenRepository.markAsUsed(rawToken);

        if (rowsUpdated == 0) {
            // already used: handle race condition or theft
            log.warn("RefreshTokenOrchestrator: Token already used (Race/Reuse) userId={}", user.getId());

            // Check Redis Grace Period (Handling Network Retries) if user was not able to get response(tokens)
            // generated in previous request, we will check that token is stored in redis or not
            // If token is stored in redis we will return that cached tokens, else we will detect it is token theft and reuse act.
            String graceKey = "refresh_grace:" + rawToken;
            String cachedTokens = redisTemplate.opsForValue().get(graceKey);

            if (cachedTokens != null) {
                log.info("RefreshTokenOrchestrator: Grace period hit. Returning cached tokens.");
                try {
                    return objectMapper.readValue(cachedTokens, AuthenticationResult.class);
                } catch (Exception e) {
                    log.error("Failed to parse cached tokens", e);
                }
            }

            // No Grace Period -> Real Token Theft
            log.error("RefreshTokenOrchestrator: SECURITY ALERT - Token Reuse Detected! invalidating all sessions for userId={}", user.getId());

            // for security, Invalidate ALL sessions for this user immediately
            refreshTokenRepository.invalidateAllForUser(user.getId());
            user.incrementTokenVersion();
            userRepository.save(user);

            auditService.record(AuditAction.REFRESH_TOKEN_REUSE, user.getId(), user.getId(),
                    "Token reuse detected", null, null);

            throw new InvalidCredentialsException("Session compromised. Please login again.");
        }

        // Rotate Token
        try {
            // Generate new tokens
            AuthenticationResult result = tokenService.generateTokens(user, ctx);

            // Save new tokens to redis, if the client retries the old token within the 60s, we return this result.
            String graceKey = "refresh_grace:" + rawToken;
            String jsonResult = objectMapper.writeValueAsString(result);

            redisTemplate.opsForValue().set(graceKey, jsonResult, 60, TimeUnit.SECONDS);

            // Record success
            try {
                loginActivityService.recordSuccess(user.getId(), user.getEmail(), ctx.ip(), ctx.userAgent());
            } catch (Exception ignored) {
            }

            log.info("RefreshTokenOrchestrator: finished for email={}", user.getEmail());

            return result;

        } catch (Exception ex) {
            log.error("RefreshTokenOrchestrator: rotation failed", ex);
            throw new TokenGenerationException("Unable to refresh token", ex);
        }
    }

}
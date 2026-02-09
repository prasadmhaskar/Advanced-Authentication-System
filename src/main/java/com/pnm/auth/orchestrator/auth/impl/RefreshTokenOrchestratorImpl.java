package com.pnm.auth.orchestrator.auth.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pnm.auth.domain.entity.RefreshToken;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuditAction;
import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.event.SuccessEvent;
import com.pnm.auth.exception.custom.InvalidCredentialsException;
import com.pnm.auth.exception.custom.InvalidTokenException;
import com.pnm.auth.exception.custom.TokenGenerationException;
import com.pnm.auth.exception.custom.UserNotFoundException;
import com.pnm.auth.orchestrator.auth.interfaces.RefreshTokenOrchestrator;
import com.pnm.auth.repository.RefreshTokenRepository;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.service.impl.cache.CacheManagementService;
import com.pnm.auth.service.interfaces.audit.AuditService;
import com.pnm.auth.service.interfaces.auth.TokenService;
import com.pnm.auth.util.MaskingUtil;
import com.pnm.auth.util.UserAgentParser;
import com.pnm.auth.web.context.RequestContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
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
    private final AuditService auditService;
    private final UserRepository userRepository;
    private final ApplicationEventPublisher eventPublisher;
    private final CacheManagementService cacheManagementService;

    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;

    private static final String REFRESH_GRACE_KEY_PREFIX = "refresh_grace:";

    @Override
    @Transactional(noRollbackFor = {InvalidCredentialsException.class})
    public AuthenticationResult refresh(String rawToken, RequestContext ctx) {

        log.info("RefreshTokenOrchestrator: started");

        // Load token
        RefreshToken stored = refreshTokenRepository.findByToken(rawToken)
                .orElseThrow(() -> new InvalidTokenException("Invalid refresh token"));

        User user = stored.getUser();

        // Validate expiration and status
        if (stored.isInvalidated() || stored.getExpiresAt().isBefore(LocalDateTime.now())) {
            log.warn("RefreshTokenOrchestrator: expired/invalidated token userId={}", user.getId());
            throw new InvalidTokenException("Refresh token expired");
        }

        // Validate device signature
        String currentDeviceSignature = UserAgentParser.parse(ctx.userAgent()).getSignature();

        if (!stored.getDeviceSignature().equals(currentDeviceSignature)) {
            throw new InvalidTokenException("Refresh token used from different device");
        }

        // Reuse detection
        int rowsUpdated = refreshTokenRepository.markAsUsed(rawToken);

        if (rowsUpdated == 0) {
            return handlePotentialReuse(rawToken, user, ctx);
        }

        // Generate New Tokens
        try {
            AuthenticationResult result = tokenService.generateTokens(user, ctx);

            // Cache for a grace period to handle network retries
            cacheResultForGracePeriod(rawToken, result);

            eventPublisher.publishEvent(new SuccessEvent(user.getId(), user.getEmail(), ctx.ip(), ctx.userAgent(), "Tokens refreshed"));
            log.info("RefreshTokenOrchestrator: finished for email={}", MaskingUtil.maskEmail(user.getEmail()));

            return result;

        } catch (Exception ex) {
            log.error("RefreshTokenOrchestrator: rotation failed", ex);
            throw new TokenGenerationException("Unable to refresh token", ex);
        }
    }


    private AuthenticationResult handlePotentialReuse(String rawToken, User user, RequestContext ctx) {
        log.warn("RefreshTokenOrchestrator: Token already used (Race/Reuse) userId={}", user.getId());

        // Check a grace period
        String graceKey = REFRESH_GRACE_KEY_PREFIX + rawToken;

        // Retry Mechanism
        // We poll Redis 3 times with 150ms delays.
        // This gives the parallel "Winner" thread ~450ms to finish generating tokens and populate Redis.
        for (int i = 0; i < 3; i++) {
            String cachedTokens = redisTemplate.opsForValue().get(graceKey);

            if (cachedTokens != null) {
                log.info("RefreshTokenOrchestrator: Grace period hit on attempt {}. Returning cached tokens.", i + 1);
                try {
                    return objectMapper.readValue(cachedTokens, AuthenticationResult.class);
                } catch (Exception e) {
                    log.error("Failed to parse cached tokens", e);
                    break; // Fall through to lockout
                }
            }

            try {
                // Sleep briefly to let the other thread finish
                TimeUnit.MILLISECONDS.sleep(150);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }

        // Real theft detected - Lockout
        executeSecurityLockout(user, ctx);
        throw new InvalidCredentialsException("Session compromised. Please login again.");
    }

    private void executeSecurityLockout(User user, RequestContext ctx) {
        log.error("RefreshTokenOrchestrator: SECURITY ALERT - Token Reuse! Invalidating sessions for userId={}", user.getId());

        Long userId = user.getId();

        // Invalidate all tokens
        refreshTokenRepository.invalidateAllForUser(userId);

        // Refetch user
        User managedUser = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found during security invalidation"));

        // Increment token version (invalidates jwts)
        managedUser.incrementTokenVersion();
        userRepository.save(managedUser);

        // Evict cache
        cacheManagementService.evictUserFromCache(managedUser.getEmail());

        // Audit toke reuse
        auditService.recordAudit(AuditAction.REFRESH_TOKEN_REUSE, managedUser.getId(), managedUser.getId(),
                "Token reuse detected", ctx.ip(), ctx.userAgent());

        throw new InvalidCredentialsException("Session compromised. Please login again.");
    }

    private void cacheResultForGracePeriod(String rawToken, AuthenticationResult result) {
        try {
            String graceKey = REFRESH_GRACE_KEY_PREFIX + rawToken;
            String jsonResult = objectMapper.writeValueAsString(result);
            redisTemplate.opsForValue().set(graceKey, jsonResult, 60, TimeUnit.SECONDS);
        } catch (Exception e) {
            log.error("Failed to cache refresh token result for grace period", e);
        }
    }
}
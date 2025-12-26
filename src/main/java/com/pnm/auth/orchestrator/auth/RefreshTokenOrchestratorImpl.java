package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.response.UserResponse;
import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.domain.entity.RefreshToken;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuditAction;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.exception.custom.InvalidCredentialsException;
import com.pnm.auth.exception.custom.InvalidTokenException;
import com.pnm.auth.exception.custom.TokenGenerationException;
import com.pnm.auth.repository.RefreshTokenRepository;
import com.pnm.auth.util.JwtUtil;
import com.pnm.auth.service.audit.AuditService;
import com.pnm.auth.service.login.LoginActivityService;
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
public class RefreshTokenOrchestratorImpl implements RefreshTokenOrchestrator {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtUtil jwtUtil;
    private final TokenService tokenService;
    private final LoginActivityService loginActivityService;
    private final AuditService auditService;

    @Override
    @Transactional
    @Audit(action = AuditAction.REFRESH_TOKEN_ROTATION,
            description = "Refreshing access token")
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

        // 3️⃣ Reuse detection (CRITICAL SECURITY)
        if (stored.isUsed()) {
            log.error("RefreshTokenOrchestrator: TOKEN REUSE DETECTED userId={}", user.getId());

            refreshTokenRepository.invalidateAllForUser(user.getId());

            auditService.record(
                    AuditAction.REFRESH_TOKEN_REUSE,
                    user.getId(),
                    user.getId(),
                    "Refresh token reuse detected",
                    null, null
            );

            throw new InvalidCredentialsException(
                    "Session compromised. Please login again."
            );
        }

        // 4️⃣ Rotate token (ONLY place for try–catch)
        try {
            stored.setUsed(true);
            refreshTokenRepository.save(stored);

            AuthenticationResult tokens = tokenService.generateTokens(user);

            // Best effort logging
            try {
                loginActivityService.recordSuccess(user.getId(), user.getEmail(), ip, userAgent);
            } catch (Exception ex) {
                log.warn("RefreshTokenOrchestrator: activity log failed userId={}", user.getId());
            }

            log.info("RefreshTokenOrchestrator: completed userId={}", user.getId());

            return AuthenticationResult.builder()
                    .outcome(AuthOutcome.TOKEN_REFRESHED)
                    .accessToken(tokens.getAccessToken())
                    .refreshToken(tokens.getRefreshToken())
                    .user(UserResponse.from(user))
                    .message("Token refreshed successfully")
                    .build();

        } catch (Exception ex) {
            log.error("RefreshTokenOrchestrator: rotation failed userId={} msg={}",
                    user.getId(), ex.getMessage(), ex);

            loginActivityService.recordFailure(
                    user.getEmail(),"Refresh token rotation failed", ip, userAgent);

            throw new TokenGenerationException(
                    "Unable to refresh token. Please login again.",
                    ex);
        }
    }

    private String safeTokenPrefix(String token) {
        return token.length() > 8 ? token.substring(0, 8) : token;
    }
}


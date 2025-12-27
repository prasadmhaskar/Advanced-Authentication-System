package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.request.ChangePasswordRequest;
import com.pnm.auth.dto.response.UserResponse;
import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuditAction;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.exception.custom.*;
import com.pnm.auth.repository.RefreshTokenRepository;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.util.JwtUtil;
import com.pnm.auth.service.login.LoginActivityService;
import com.pnm.auth.service.auth.TokenService;
import com.pnm.auth.util.Audit;
import com.pnm.auth.util.BlacklistedTokenStore;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Caching;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class ChangePasswordOrchestratorImpl implements ChangePasswordOrchestrator {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenRepository refreshTokenRepository;
    private final BlacklistedTokenStore blacklistedTokenStore;
    private final TokenService tokenService;
    private final LoginActivityService loginActivityService;

    @Override
    @Transactional
    @Caching(evict = {@CacheEvict(value = "users", key = "#accessToken"),
            @CacheEvict(value = "users.list", allEntries = true)})
    @Audit(action = AuditAction.CHANGE_PASSWORD, description = "User password change")
    public AuthenticationResult changePassword(String accessToken, ChangePasswordRequest request, String ip, String userAgent)
    {
        log.info("ChangePasswordOrchestrator: started");

        // --------------------------------------------------
        // 1️⃣ Validate access token
        // --------------------------------------------------
        if (accessToken == null || accessToken.isBlank()) {
            log.warn("ChangePasswordOrchestrator: missing token");
            throw new InvalidTokenException("Missing access token");
        }

        if (jwtUtil.isTokenExpired(accessToken)) {
            log.warn("ChangePasswordOrchestrator: token expired");
            throw new InvalidTokenException("Access token expired");
        }

        // --------------------------------------------------
        // 2️⃣ Extract user identity
        // --------------------------------------------------
        String email;
        try {
            email = jwtUtil.extractUsername(accessToken);
        } catch (Exception ex) {
            log.warn("ChangePasswordOrchestrator: failed to parse token msg={}", ex.getMessage());
            throw new InvalidTokenException("Invalid access token");
        }

        // --------------------------------------------------
        // 3️⃣ Load and validate user
        // --------------------------------------------------
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("ChangePasswordOrchestrator: user not found email={}", email);
                    return new UserNotFoundException("User not found");
                });

        if (!user.isActive()) {
            log.warn("ChangePasswordOrchestrator: blocked user attempted password change email={}", email);
            throw new AccountBlockedException("Your account has been blocked.");
        }

        // --------------------------------------------------
        // 4️⃣ Validate old password
        // --------------------------------------------------
        if (!passwordEncoder.matches(request.getOldPassword(), user.getPassword())) {
            log.warn("ChangePasswordOrchestrator: old password mismatch email={}", email);
            throw new InvalidCredentialsException("Old password is incorrect.");
        }

        // Prevent password reuse
        if (passwordEncoder.matches(request.getNewPassword(), user.getPassword())) {
            log.warn("ChangePasswordOrchestrator: new password same as old email={}", email);
            throw new InvalidCredentialsException("New password cannot be same as old password.");
        }

        // --------------------------------------------------
        // 5️⃣ Update password
        // --------------------------------------------------
        try {
            user.setPassword(passwordEncoder.encode(request.getNewPassword()));
            userRepository.save(user);

            // Invalidate all refresh tokens
            refreshTokenRepository.invalidateAllForUser(user.getId());

            // Blacklist current access token
            Claims claims = jwtUtil.extractAllClaims(accessToken);
            blacklistedTokenStore.blacklistToken(
                    accessToken,
                    claims.getExpiration().getTime()
            );

        } catch (Exception ex) {
            log.error("ChangePasswordOrchestrator: failed to update password email={} msg={}",
                    email, ex.getMessage(), ex);

            loginActivityService.recordFailure(email, "Password change failed", ip, userAgent);
            throw new PasswordChangeException("Unable to change password. Please try again later.");
        }

        // --------------------------------------------------
        // 6️⃣ Generate fresh tokens
        // --------------------------------------------------
        AuthenticationResult tokens = tokenService.generateTokens(user);

        // --------------------------------------------------
        // 7️⃣ Audit success (best-effort)
        // --------------------------------------------------
        try {
            loginActivityService.recordSuccess(user.getId(), email, ip, userAgent);
        } catch (Exception ex) {
            log.warn("ChangePasswordOrchestrator: failed to record success email={}", email);
        }

        log.info("ChangePasswordOrchestrator: completed successfully email={}", email);

        return AuthenticationResult.builder()
                .outcome(AuthOutcome.SUCCESS)
                .accessToken(tokens.getAccessToken())
                .refreshToken(tokens.getRefreshToken())
                .message("Password changed successfully")
                .user(UserResponse.from(user))
                .build();
    }
}


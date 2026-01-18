package com.pnm.auth.orchestrator.auth.impl;

import com.pnm.auth.domain.entity.RefreshToken;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.dto.request.LogoutRequest;
import com.pnm.auth.exception.custom.InvalidCredentialsException;
import com.pnm.auth.exception.custom.InvalidTokenException;
import com.pnm.auth.exception.custom.UserNotFoundException;
import com.pnm.auth.orchestrator.auth.LogoutOrchestrator;
import com.pnm.auth.repository.RefreshTokenRepository;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.service.impl.cache.CacheManagementService;
import com.pnm.auth.util.BlacklistedTokenStore;
import com.pnm.auth.util.JwtUtil;
import com.pnm.auth.web.context.RequestContext;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


@Slf4j
@RequiredArgsConstructor
@Service
public class LogoutOrchestratorImpl implements LogoutOrchestrator {
    private final JwtUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final CacheManagementService cacheManagementService;
    private final BlacklistedTokenStore blacklistedTokenStore;

    @Transactional
    public void logout(
            LogoutRequest request,
            HttpServletRequest httpServletRequest
    ) {

        log.info("LogoutOrchestrator: started");

        // Extract access token from header
        String accessToken = extractAccessToken(httpServletRequest);

        // Extract user email
        String email;
        try {
            email = jwtUtil.extractUsername(accessToken);
        } catch (Exception e) {
            throw new InvalidTokenException("Invalid access token");
        }

        // Refresh token validation
        if (request != null && request.getRefreshToken() != null) {
            RefreshToken refreshToken = refreshTokenRepository
                    .findByToken(request.getRefreshToken())
                    .orElseThrow(() -> new InvalidTokenException("Invalid refresh token"));

            if (!refreshToken.getUser().getEmail().equals(email)) {
                throw new InvalidCredentialsException("Token ownership mismatch");
            }

            long expirationTimestamp = jwtUtil.getExpirationTimestamp(accessToken);
            blacklistedTokenStore.blacklistToken(accessToken, expirationTimestamp);

            refreshTokenRepository.delete(refreshToken);
        }

        // if a user selects logout from all devices, then we will do this
        if (request != null && request.getLogoutFromAllDevices()){
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new UserNotFoundException("User not found"));

            // Kill refresh token via token Version
            user.incrementTokenVersion();
            userRepository.save(user);

            // Delete user details from cache
            cacheManagementService.evictUserFromCache(user.getEmail());

            refreshTokenRepository.invalidateAllForUser(user.getId());

        }
        log.info("LogoutOrchestrator: finished for email={}", email);
    }

    private String extractAccessToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");

        if (header == null || !header.startsWith("Bearer ")) {
            throw new InvalidTokenException("Missing Authorization header");
        }
        return header.substring(7);
    }
}

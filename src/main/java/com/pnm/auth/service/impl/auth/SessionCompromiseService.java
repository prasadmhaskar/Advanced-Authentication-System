package com.pnm.auth.service.impl.auth;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.exception.custom.UserNotFoundException;
import com.pnm.auth.repository.RefreshTokenRepository;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.service.impl.cache.CacheManagementService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Performs the database-side session revocation for a confirmed compromise.
 * The token-version change invalidates every already-issued access token, while
 * invalidating refresh tokens prevents a new access token from being minted.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SessionCompromiseService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final CacheManagementService cacheManagementService;

    @Transactional
    public void revokeAllSessions(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found during security invalidation"));

        refreshTokenRepository.invalidateAllForUser(userId);
        user.incrementTokenVersion();
        userRepository.save(user);
        cacheManagementService.evictUserFromCache(user.getEmail());

        log.warn("Revoked all sessions for confirmed access-token compromise, userId={}", userId);
    }
}

package com.pnm.auth.service.auth;

import com.pnm.auth.dto.response.UserDetailsResponse;
import com.pnm.auth.entity.User;
import com.pnm.auth.exception.AccountBlockedException;
import com.pnm.auth.exception.InvalidTokenException;
import com.pnm.auth.exception.UserNotFoundException;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserContextOrchestratorImpl implements UserContextOrchestrator {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    @Cacheable(value = "users", key = "#accessToken")
    public UserDetailsResponse getCurrentUser(String accessToken) {

        log.info("UserContextOrchestrator: fetching user context");

        // 1️⃣ Token present?
        if (accessToken == null || accessToken.isBlank()) {
            log.warn("UserContextOrchestrator: missing access token");
            throw new InvalidTokenException("Missing or invalid Authorization header");
        }

        // 2️⃣ Token expired?
        if (jwtUtil.isTokenExpired(accessToken)) {
            log.warn("UserContextOrchestrator: token expired");
            throw new InvalidTokenException("Access token expired");
        }

        // 3️⃣ Extract email
        String email;
        try {
            email = jwtUtil.extractUsername(accessToken);
        } catch (Exception ex) {
            log.warn("UserContextOrchestrator: token parsing failed msg={}", ex.getMessage());
            throw new InvalidTokenException("Invalid access token");
        }

        log.debug("UserContextOrchestrator: extracted email={}", email);

        // 4️⃣ Load user
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("UserContextOrchestrator: user not found email={}", email);
                    return new UserNotFoundException("User not found");
                });

        // 5️⃣ Active check
        if (!user.isActive()) {
            log.warn("UserContextOrchestrator: blocked user requested /me email={}", email);
            throw new AccountBlockedException("Your account has been blocked");
        }

        // 6️⃣ Build response DTO
        return new UserDetailsResponse(
                user.getFullName(),
                user.getEmail(),
                user.getRoles(),
                user.getAuthProviderType(),
                user.getCreatedAt(),
                user.getUpdatedAt()
        );
    }
}


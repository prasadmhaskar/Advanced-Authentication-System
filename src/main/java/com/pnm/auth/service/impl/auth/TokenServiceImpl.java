package com.pnm.auth.service.impl.auth;

import com.pnm.auth.dto.response.UserResponse;
import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.domain.entity.RefreshToken;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.exception.custom.TokenGenerationException;
import com.pnm.auth.repository.RefreshTokenRepository;
import com.pnm.auth.util.JwtUtil;
import com.pnm.auth.service.auth.TokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenServiceImpl implements TokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtUtil jwtUtil;

    @Value("${jwt.refresh.expiration}")
    private Long jwtRefreshExpiration;

    @Override
    public AuthenticationResult generateTokens(User user) {

        log.info("TokenService: generating tokens for email={}", user.getEmail());

        try {
            // --------------------------------------------------------
            // 1) Invalidate OLD refresh tokens
            // --------------------------------------------------------
            refreshTokenRepository.invalidateAllForUser(user.getId());

            // --------------------------------------------------------
            // 2) Create new access + refresh tokens
            // --------------------------------------------------------
            String accessToken = jwtUtil.generateAccessToken(user);
            String refreshToken = jwtUtil.generateRefreshToken(user);

            // --------------------------------------------------------
            // 3) Save new refresh token entity
            // --------------------------------------------------------
            RefreshToken token = new RefreshToken();
            token.setToken(refreshToken);
            token.setUser(user);
            token.setCreatedAt(LocalDateTime.now());
            token.setExpiresAt(LocalDateTime.now().plus(jwtRefreshExpiration, ChronoUnit.MILLIS));
            token.setUsed(false);
            token.setInvalidated(false);

            refreshTokenRepository.save(token);


            log.info("TokenService: tokens generated successfully for user={}", user.getEmail());

            // --------------------------------------------------------
            // 5) Return unified AuthenticationResult
            // --------------------------------------------------------
            return AuthenticationResult.builder()
                    .outcome(AuthOutcome.SUCCESS)
                    .user(UserResponse.from(user))
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .message("Login successful")
                    .build();

        } catch (Exception ex) {
            log.error("TokenService: token generation failed for userId={}", user.getId(), ex);
            throw new TokenGenerationException("Token generation failed", ex);
        }

    }
}

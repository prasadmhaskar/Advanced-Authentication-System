package com.pnm.auth.service.auth;

import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.entity.RefreshToken;
import com.pnm.auth.entity.User;
import com.pnm.auth.enums.AuthOutcome;
import com.pnm.auth.repository.RefreshTokenRepository;
import com.pnm.auth.security.JwtUtil;
import com.pnm.auth.service.LoginActivityService;
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
    private final LoginActivityService loginActivityService;

    @Value("${jwt.refresh.expiration}")
    private Long jwtRefreshExpirationMillis;



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
            token.setExpiresAt(LocalDateTime.now().plus(jwtRefreshExpirationMillis, ChronoUnit.MILLIS));
            token.setUsed(false);
            token.setInvalidated(false);

            refreshTokenRepository.save(token);

            // --------------------------------------------------------
            // 4) Record login success (non-critical)
            // --------------------------------------------------------
            try {
                loginActivityService.recordSuccess(user.getId(), user.getEmail());
            } catch (Exception ex) {
                log.error("TokenService: failed to record login success for userId={} msg={}",
                        user.getId(), ex.getMessage(), ex);
            }

            log.info("TokenService: tokens generated successfully for user={}", user.getEmail());

            // --------------------------------------------------------
            // 5) Return unified AuthenticationResult
            // --------------------------------------------------------
            return AuthenticationResult.builder()
                    .outcome(AuthOutcome.SUCCESS)
                    .user(user)
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .message("Login successful")
                    .build();

        } catch (Exception ex) {
            log.error("TokenService: failed to generate tokens for user={} msg={}",
                    user.getEmail(), ex.getMessage(), ex);

            throw new RuntimeException("Token generation failed. Please try again later.");
        }
    }
}

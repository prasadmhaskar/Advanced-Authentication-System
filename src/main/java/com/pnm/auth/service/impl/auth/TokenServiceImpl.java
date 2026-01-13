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
import com.pnm.auth.util.MaskingUtil;
import com.pnm.auth.util.UserAgentParser;
import com.pnm.auth.web.context.RequestContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenServiceImpl implements TokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtUtil jwtUtil;


    private static final int MAX_SESSIONS = 5;

    @Value("${jwt.refresh.expiration}")
    private Long jwtRefreshExpiration;

    @Override
    @Transactional
    public AuthenticationResult generateTokens(User user, RequestContext ctx) {

        log.info("TokenService: generating tokens for email={}", MaskingUtil.maskEmail(user.getEmail()));

        try {
            refreshTokenRepository.deleteOldestSessions(user.getId(), MAX_SESSIONS - 1);

            String deviceSignature = UserAgentParser
                    .parse(ctx.userAgent())
                    .getSignature();


            // 2) Create new access + refresh tokens
            String accessToken = jwtUtil.generateAccessToken(user);
            String refreshToken = jwtUtil.generateRefreshToken(user);

            // 3) Save new refresh token entity
            RefreshToken token = new RefreshToken();
            token.setToken(refreshToken);
            token.setUser(user);
            token.setCreatedAt(LocalDateTime.now());
            token.setExpiresAt(LocalDateTime.now().plus(jwtRefreshExpiration, ChronoUnit.MILLIS));
            token.setDeviceSignature(deviceSignature);
            token.setUsed(false);
            token.setInvalidated(false);

            refreshTokenRepository.save(token);

            log.info("TokenService: tokens generated successfully for user={}", MaskingUtil.maskEmail(user.getEmail()));

            // 5) Return unified AuthenticationResult
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

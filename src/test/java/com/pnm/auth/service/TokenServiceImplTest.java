package com.pnm.auth.service;


import com.pnm.auth.domain.entity.RefreshToken;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.exception.custom.TokenGenerationException;
import com.pnm.auth.repository.RefreshTokenRepository;
import com.pnm.auth.service.impl.auth.TokenServiceImpl;
import com.pnm.auth.util.JwtUtil;
import com.pnm.auth.web.context.RequestContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TokenServiceImplTest {

    private static final long REFRESH_EXPIRATION_MILLIS = 60_000L;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private JwtUtil jwtUtil;

    @InjectMocks
    private TokenServiceImpl tokenService;

    @Captor
    private ArgumentCaptor<RefreshToken> refreshTokenCaptor;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(tokenService, "jwtRefreshExpiration", REFRESH_EXPIRATION_MILLIS);
    }

    @Test
    void generateTokens_createsAndStoresRefreshToken() {
        User user = new User();
        user.setId(42L);
        user.setFullName("Ada Lovelace");
        user.setEmail("ada@example.com");
        user.setRoles(List.of("ROLE_USER"));

        RequestContext context = new RequestContext(
                "127.0.0.1",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "/login"
        );

        when(jwtUtil.generateAccessToken(user)).thenReturn("access-token");
        when(jwtUtil.generateRefreshToken(user)).thenReturn("refresh-token");

        AuthenticationResult result = tokenService.generateTokens(user, context);

        verify(refreshTokenRepository).deleteOldestSessions(42L, 4);
        verify(refreshTokenRepository).save(refreshTokenCaptor.capture());

        RefreshToken savedToken = refreshTokenCaptor.getValue();
        assertThat(savedToken.getToken()).isEqualTo("refresh-token");
        assertThat(savedToken.getUser()).isSameAs(user);
        assertThat(savedToken.getDeviceSignature()).isEqualTo("Chrome_Windows_DESKTOP");
        assertThat(savedToken.isUsed()).isFalse();
        assertThat(savedToken.isInvalidated()).isFalse();
        assertThat(ChronoUnit.MILLIS.between(savedToken.getCreatedAt(), savedToken.getExpiresAt()))
                .isEqualTo(REFRESH_EXPIRATION_MILLIS);

        assertThat(result.getOutcome()).isEqualTo(AuthOutcome.SUCCESS);
        assertThat(result.getAccessToken()).isEqualTo("access-token");
        assertThat(result.getRefreshToken()).isEqualTo("refresh-token");
        assertThat(result.getUser().getEmail()).isEqualTo("ada@example.com");
        assertThat(result.getMessage()).isEqualTo("Login successful");
    }

    @Test
    void generateTokens_throwsWhenPersistenceFails() {
        User user = new User();
        user.setId(99L);
        user.setEmail("grace@example.com");

        RequestContext context = new RequestContext("127.0.0.1", "", "/login");

        doThrow(new IllegalStateException("boom"))
                .when(refreshTokenRepository)
                .deleteOldestSessions(99L, 4);

        assertThatThrownBy(() -> tokenService.generateTokens(user, context))
                .isInstanceOf(TokenGenerationException.class)
                .hasMessageContaining("Token generation failed");

        verify(refreshTokenRepository, never()).save(any(RefreshToken.class));
        verifyNoInteractions(jwtUtil);
    }
}


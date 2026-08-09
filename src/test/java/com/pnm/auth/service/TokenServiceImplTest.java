package com.pnm.auth.service;

import com.pnm.auth.domain.entity.RefreshToken;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.event.SessionCleanupListener.SessionCleanupEvent;
import com.pnm.auth.exception.custom.TokenGenerationException;
import com.pnm.auth.repository.RefreshTokenRepository;
import com.pnm.auth.service.impl.auth.TokenServiceImpl;
import com.pnm.auth.util.JwtUtil;
import com.pnm.auth.util.RefreshTokenUtil;
import com.pnm.auth.web.context.RequestContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within; // FIXED: Correct Static Import
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TokenServiceImplTest {

    private static final long REFRESH_EXPIRATION_MILLIS = 60_000L;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private RefreshTokenUtil refreshTokenUtil;

    @Mock
    private ApplicationEventPublisher eventPublisher;

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
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "/login"
        );

        when(jwtUtil.generateAccessToken(user)).thenReturn("access-token");
        when(refreshTokenUtil.generateToken()).thenReturn("refresh-token");
        when(refreshTokenUtil.hash("refresh-token")).thenReturn("refresh-token-hash");

        AuthenticationResult result = tokenService.generateTokens(user, context);

        verify(eventPublisher).publishEvent(any(SessionCleanupEvent.class));
        verify(refreshTokenRepository).save(refreshTokenCaptor.capture());

        RefreshToken savedToken = refreshTokenCaptor.getValue();
        assertThat(savedToken.getTokenHash()).isEqualTo("refresh-token-hash");
        assertThat(savedToken.getTokenHash()).isNotEqualTo(result.getRefreshToken());
        assertThat(savedToken.getUser()).isSameAs(user);
        assertThat(savedToken.getDeviceSignature()).isEqualTo("Chrome_Windows_DESKTOP");
        assertThat(savedToken.isUsed()).isFalse();
        assertThat(savedToken.isInvalidated()).isFalse();

        // FIXED: Using correctly imported 'within'
        assertThat(savedToken.getExpiresAt()).isCloseTo(
                savedToken.getCreatedAt().plus(REFRESH_EXPIRATION_MILLIS, ChronoUnit.MILLIS),
                within(1, ChronoUnit.SECONDS)
        );

        assertThat(result.getOutcome()).isEqualTo(AuthOutcome.SUCCESS);
        assertThat(result.getAccessToken()).isEqualTo("access-token");
        assertThat(result.getRefreshToken()).isEqualTo("refresh-token");
    }

    @Test
    void generateTokens_throwsWhenPersistenceFails() {
        User user = new User();
        user.setId(99L);
        user.setEmail("grace@example.com");

        RequestContext context = new RequestContext("127.0.0.1", "", "/login");

        when(jwtUtil.generateAccessToken(user)).thenReturn("acc");
        when(refreshTokenUtil.generateToken()).thenReturn("ref");
        when(refreshTokenUtil.hash("ref")).thenReturn("ref-hash");

        doThrow(new IllegalStateException("DB Error"))
                .when(refreshTokenRepository)
                .save(any(RefreshToken.class));

        assertThatThrownBy(() -> tokenService.generateTokens(user, context))
                .isInstanceOf(TokenGenerationException.class)
                .hasMessageContaining("Token generation failed");

        verify(eventPublisher).publishEvent(any(SessionCleanupEvent.class));
    }
}

package com.pnm.auth.orchestrator;


import com.pnm.auth.domain.entity.MfaToken;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.dto.request.OtpVerifyRequest;
import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.event.FailureEvent;
import com.pnm.auth.event.SuccessEvent;
import com.pnm.auth.exception.custom.AccountBlockedException;
import com.pnm.auth.exception.custom.InvalidCredentialsException;
import com.pnm.auth.exception.custom.InvalidTokenException;
import com.pnm.auth.orchestrator.auth.impl.VerifyOtpOrchestratorImpl;
import com.pnm.auth.repository.MfaTokenRepository;
import com.pnm.auth.service.interfaces.auth.TokenService;
import com.pnm.auth.service.interfaces.device.DeviceTrustService;
import com.pnm.auth.service.interfaces.ipmonitoring.IpMonitoringService;
import com.pnm.auth.util.UserAgentParser;
import com.pnm.auth.web.context.RequestContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class VerifyOtpOrchestratorImplTest {

    @Mock
    private MfaTokenRepository mfaTokenRepository;

    @Mock
    private TokenService tokenService;

    @Mock
    private DeviceTrustService deviceTrustService;

    @Mock
    private IpMonitoringService ipMonitoringService;

    @Mock
    private ApplicationEventPublisher eventPublisher;

    @InjectMocks
    private VerifyOtpOrchestratorImpl orchestrator;

    @Test
    void verifyReturnsTokensAndPublishesSuccessEvent() {
        User user = buildUser(true);
        MfaToken token = buildToken(user, false, LocalDateTime.now().plusMinutes(5));
        OtpVerifyRequest request = buildRequest(token.getId(), " 123456 ");
        String userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        RequestContext ctx = new RequestContext("10.0.0.2", userAgent, "/verify");

        when(mfaTokenRepository.findByIdAndUsedFalse(token.getId())).thenReturn(Optional.of(token));
        when(mfaTokenRepository.markAsUsed(token.getId())).thenReturn(1);
        when(tokenService.generateTokens(eq(user), eq(ctx)))
                .thenReturn(AuthenticationResult.builder()
                        .accessToken("access-token")
                        .refreshToken("refresh-token")
                        .build());

        AuthenticationResult result = orchestrator.verify(request, ctx);

        assertThat(result.getOutcome()).isEqualTo(AuthOutcome.SUCCESS);
        assertThat(result.getAccessToken()).isEqualTo("access-token");
        assertThat(result.getRefreshToken()).isEqualTo("refresh-token");
        assertThat(result.getMessage()).isEqualTo("MFA OTP verified successfully");
        assertThat(result.getUser()).isNotNull();

        ArgumentCaptor<Object> eventCaptor = ArgumentCaptor.forClass(Object.class);
        verify(eventPublisher).publishEvent(eventCaptor.capture());
        assertThat(eventCaptor.getValue()).isInstanceOf(SuccessEvent.class);
        verify(ipMonitoringService).recordIpDetails(user.getId(), ctx.ip(), ctx.userAgent());
        var deviceInfo = UserAgentParser.parse(userAgent);
        verify(deviceTrustService).trustDevice(user.getId(), deviceInfo.getSignature(), deviceInfo.getDeviceName());
    }

    @Test
    void verifyReturnsRiskBasedMessage() {
        User user = buildUser(true);
        MfaToken token = buildToken(user, true, LocalDateTime.now().plusMinutes(5));
        OtpVerifyRequest request = buildRequest(token.getId(), "123456");
        RequestContext ctx = new RequestContext("10.0.0.2", "Mozilla/5.0 Chrome/115", "/verify");

        when(mfaTokenRepository.findByIdAndUsedFalse(token.getId())).thenReturn(Optional.of(token));
        when(mfaTokenRepository.markAsUsed(token.getId())).thenReturn(1);
        when(tokenService.generateTokens(eq(user), eq(ctx)))
                .thenReturn(AuthenticationResult.builder()
                        .accessToken("access-token")
                        .refreshToken("refresh-token")
                        .build());

        AuthenticationResult result = orchestrator.verify(request, ctx);

        assertThat(result.getMessage()).isEqualTo("Risk-based OTP verified successfully");
    }

    @Test
    void verifyPublishesFailureEventWhenUserBlocked() {
        User user = buildUser(false);
        MfaToken token = buildToken(user, false, LocalDateTime.now().plusMinutes(5));
        OtpVerifyRequest request = buildRequest(token.getId(), "123456");
        RequestContext ctx = new RequestContext("10.0.0.2", "Mozilla/5.0", "/verify");

        when(mfaTokenRepository.findByIdAndUsedFalse(token.getId())).thenReturn(Optional.of(token));

        assertThatThrownBy(() -> orchestrator.verify(request, ctx))
                .isInstanceOf(AccountBlockedException.class)
                .hasMessage("Your account has been blocked.");

        verify(eventPublisher).publishEvent(any(FailureEvent.class));
        verify(tokenService, never()).generateTokens(any(), any());
    }

    @Test
    void verifyRejectsMissingToken() {
        OtpVerifyRequest request = buildRequest(99L, "123456");
        RequestContext ctx = new RequestContext("10.0.0.2", "Mozilla/5.0", "/verify");

        when(mfaTokenRepository.findByIdAndUsedFalse(request.getTokenId())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> orchestrator.verify(request, ctx))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessage("OTP token not found or already used");
    }

    @Test
    void verifyRejectsExpiredToken() {
        User user = buildUser(true);
        MfaToken token = buildToken(user, false, LocalDateTime.now().minusMinutes(1));
        OtpVerifyRequest request = buildRequest(token.getId(), "123456");
        RequestContext ctx = new RequestContext("10.0.0.2", "Mozilla/5.0", "/verify");

        when(mfaTokenRepository.findByIdAndUsedFalse(token.getId())).thenReturn(Optional.of(token));

        assertThatThrownBy(() -> orchestrator.verify(request, ctx))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessage("OTP expired");
    }

    @Test
    void verifyRejectsWrongOtp() {
        User user = buildUser(true);
        MfaToken token = buildToken(user, false, LocalDateTime.now().plusMinutes(5));
        OtpVerifyRequest request = buildRequest(token.getId(), "654321");
        RequestContext ctx = new RequestContext("10.0.0.2", "Mozilla/5.0", "/verify");

        when(mfaTokenRepository.findByIdAndUsedFalse(token.getId())).thenReturn(Optional.of(token));

        assertThatThrownBy(() -> orchestrator.verify(request, ctx))
                .isInstanceOf(InvalidCredentialsException.class)
                .hasMessage("Invalid OTP");
    }

    @Test
    void verifyRejectsAlreadyUsedToken() {
        User user = buildUser(true);
        MfaToken token = buildToken(user, false, LocalDateTime.now().plusMinutes(5));
        OtpVerifyRequest request = buildRequest(token.getId(), "123456");
        RequestContext ctx = new RequestContext("10.0.0.2", "Mozilla/5.0", "/verify");

        when(mfaTokenRepository.findByIdAndUsedFalse(token.getId())).thenReturn(Optional.of(token));
        when(mfaTokenRepository.markAsUsed(token.getId())).thenReturn(0);

        assertThatThrownBy(() -> orchestrator.verify(request, ctx))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessage("OTP already used");
    }

    @Test
    void verifyContinuesWhenDeviceTrustOrIpMonitoringFails() {
        User user = buildUser(true);
        MfaToken token = buildToken(user, false, LocalDateTime.now().plusMinutes(5));
        OtpVerifyRequest request = buildRequest(token.getId(), "123456");
        RequestContext ctx = new RequestContext("10.0.0.2", "Mozilla/5.0 Chrome/115", "/verify");

        when(mfaTokenRepository.findByIdAndUsedFalse(token.getId())).thenReturn(Optional.of(token));
        when(mfaTokenRepository.markAsUsed(token.getId())).thenReturn(1);
        when(tokenService.generateTokens(eq(user), eq(ctx)))
                .thenReturn(AuthenticationResult.builder()
                        .accessToken("access-token")
                        .refreshToken("refresh-token")
                        .build());
        doThrow(new RuntimeException("device trust down"))
                .when(deviceTrustService)
                .trustDevice(any(), any(), any());
        doThrow(new RuntimeException("ip monitoring down"))
                .when(ipMonitoringService)
                .recordIpDetails(any(), any(), any());

        AuthenticationResult result = orchestrator.verify(request, ctx);

        assertThat(result.getOutcome()).isEqualTo(AuthOutcome.SUCCESS);
        verify(eventPublisher).publishEvent(any(SuccessEvent.class));
    }

    private static User buildUser(boolean active) {
        User user = new User();
        user.setId(7L);
        user.setFullName("Test User");
        user.setEmail("user@example.com");
        user.setEmailVerified(true);
        user.setActive(active);
        user.setMfaEnabled(true);
        return user;
    }

    private static MfaToken buildToken(User user, boolean riskBased, LocalDateTime expiresAt) {
        MfaToken token = new MfaToken();
        token.setId(42L);
        token.setUser(user);
        token.setOtp("123456");
        token.setExpiresAt(expiresAt);
        token.setUsed(false);
        token.setRiskBased(riskBased);
        return token;
    }

    private static OtpVerifyRequest buildRequest(Long tokenId, String otp) {
        OtpVerifyRequest request = new OtpVerifyRequest();
        request.setTokenId(tokenId);
        request.setOtp(otp);
        return request;
    }
}


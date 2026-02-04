package com.pnm.auth.orchestrator;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.dto.request.LoginRequest;
import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.dto.result.MfaResult;
import com.pnm.auth.dto.result.RiskResult;
import com.pnm.auth.event.FailureEvent;
import com.pnm.auth.event.SuccessEvent;
import com.pnm.auth.exception.custom.HighRiskLoginException;
import com.pnm.auth.orchestrator.auth.impl.LoginOrchestratorImpl;
import com.pnm.auth.service.interfaces.auth.MfaService;
import com.pnm.auth.service.interfaces.auth.PasswordAuthService;
import com.pnm.auth.service.interfaces.auth.TokenService;
import com.pnm.auth.service.interfaces.auth.UserValidationService;
import com.pnm.auth.service.interfaces.device.DeviceTrustService;
import com.pnm.auth.service.interfaces.email.EmailService;
import com.pnm.auth.service.interfaces.risk.RiskEngineService;
import com.pnm.auth.util.UserAgentParser;
import com.pnm.auth.web.context.RequestContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockitoAnnotations;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class LoginOrchestratorImplTest {

    private static final int HIGH_RISK_THRESHOLD = 80;
    private static final int MEDIUM_RISK_THRESHOLD = 50;

    private final UserValidationService userValidationService = mock(UserValidationService.class);
    private final PasswordAuthService passwordAuthService = mock(PasswordAuthService.class);
    private final RiskEngineService riskEngineService = mock(RiskEngineService.class);
    private final MfaService mfaService = mock(MfaService.class);
    private final TokenService tokenService = mock(TokenService.class);
    private final DeviceTrustService deviceTrustService = mock(DeviceTrustService.class);
    private final ApplicationEventPublisher eventPublisher = mock(ApplicationEventPublisher.class);
    private final EmailService emailService = mock(EmailService.class);

    private LoginOrchestratorImpl orchestrator;
    private AutoCloseable mocks;

    @BeforeEach
    void setUp() {
        mocks = MockitoAnnotations.openMocks(this);
        orchestrator = new LoginOrchestratorImpl(
                userValidationService,
                passwordAuthService,
                riskEngineService,
                mfaService,
                tokenService,
                deviceTrustService,
                eventPublisher,
                emailService
        );
        ReflectionTestUtils.setField(orchestrator, "highRiskScore", HIGH_RISK_THRESHOLD);
        ReflectionTestUtils.setField(orchestrator, "mediumRiskScore", MEDIUM_RISK_THRESHOLD);
    }

    @AfterEach
    void tearDown() throws Exception {
        mocks.close();
    }

    @Test
    void login_returnsMfaRequiredForMfaEnabledUser() {
        User user = buildUser(true);
        LoginRequest request = buildRequest();
        RequestContext ctx = new RequestContext("192.168.1.10", "Mozilla/5.0", "/login");

        when(userValidationService.findUserByEmail(request.getEmail().toLowerCase()))
                .thenReturn(Optional.of(user));
        MfaResult mfaResult = MfaResult.builder()
                .outcome(AuthOutcome.MFA_REQUIRED)
                .tokenId(22L)
                .build();
        when(mfaService.handleMfaLogin(user)).thenReturn(mfaResult);

        AuthenticationResult result = orchestrator.login(request, ctx);

        assertThat(result.getOutcome()).isEqualTo(AuthOutcome.MFA_REQUIRED);
        assertThat(result.getOtpTokenId()).isEqualTo(22L);
        assertThat(result.getMessage()).contains("OTP");
        verify(riskEngineService, never()).evaluateRisk(any(), any(), any());
        verify(tokenService, never()).generateTokens(any(), any());
    }

    @Test
    void login_returnsMediumRiskOtpWhenRiskScoreIsElevated() {
        User user = buildUser(false);
        LoginRequest request = buildRequest();
        RequestContext ctx = new RequestContext("192.168.1.11", "Mozilla/5.0", "/login");

        when(userValidationService.findUserByEmail(request.getEmail().toLowerCase()))
                .thenReturn(Optional.of(user));
        when(riskEngineService.evaluateRisk(eq(user), any(), any()))
                .thenReturn(RiskResult.builder().score(60).reasons(List.of("new-device")).build());
        MfaResult mfaResult = MfaResult.builder()
                .outcome(AuthOutcome.OTP_REQUIRED)
                .tokenId(33L)
                .build();
        when(mfaService.handleMediumRiskOtp(user)).thenReturn(mfaResult);

        AuthenticationResult result = orchestrator.login(request, ctx);

        assertThat(result.getOutcome()).isEqualTo(AuthOutcome.OTP_REQUIRED);
        assertThat(result.getOtpTokenId()).isEqualTo(33L);
        verify(tokenService, never()).generateTokens(any(), any());
        verify(eventPublisher, never()).publishEvent(isA(SuccessEvent.class));
    }

    @Test
    void login_blocksHighRiskAttemptsAndSendsAlert() {
        User user = buildUser(false);
        LoginRequest request = buildRequest();
        RequestContext ctx = new RequestContext("192.168.1.12", "Mozilla/5.0", "/login");

        when(userValidationService.findUserByEmail(request.getEmail().toLowerCase()))
                .thenReturn(Optional.of(user));
        when(riskEngineService.evaluateRisk(eq(user), any(), any()))
                .thenReturn(RiskResult.builder().score(90).reasons(List.of("impossible-travel")).build());

        assertThatThrownBy(() -> orchestrator.login(request, ctx))
                .isInstanceOf(HighRiskLoginException.class);

        verify(emailService).sendHighRiskAlert(eq(user), eq("192.168.1.12"), any(), eq(List.of("impossible-travel")));
        ArgumentCaptor<FailureEvent> eventCaptor = ArgumentCaptor.forClass(FailureEvent.class);
        verify(eventPublisher).publishEvent(eventCaptor.capture());
        assertThat(eventCaptor.getValue().message()).contains("High risk");
        verify(tokenService, never()).generateTokens(any(), any());
    }

    @Test
    void login_returnsTokensAndPublishesSuccessEvent() {
        User user = buildUser(false);
        LoginRequest request = buildRequest();
        String userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        RequestContext ctx = new RequestContext("192.168.1.13", userAgent, "/login");

        when(userValidationService.findUserByEmail(request.getEmail().toLowerCase()))
                .thenReturn(Optional.of(user));
        when(riskEngineService.evaluateRisk(eq(user), any(), any()))
                .thenReturn(RiskResult.builder().score(10).reasons(List.of()).build());
        AuthenticationResult tokenResult = AuthenticationResult.builder()
                .accessToken("access-token")
                .refreshToken("refresh-token")
                .build();
        when(tokenService.generateTokens(eq(user), eq(ctx))).thenReturn(tokenResult);

        AuthenticationResult result = orchestrator.login(request, ctx);

        assertThat(result.getOutcome()).isEqualTo(AuthOutcome.SUCCESS);
        assertThat(result.getAccessToken()).isEqualTo("access-token");
        assertThat(result.getRefreshToken()).isEqualTo("refresh-token");
        assertThat(result.getUser()).isNotNull();
        ArgumentCaptor<SuccessEvent> eventCaptor = ArgumentCaptor.forClass(SuccessEvent.class);
        verify(eventPublisher).publishEvent(eventCaptor.capture());
        assertThat(eventCaptor.getValue().message()).contains("Email login successful");
        var deviceInfo = UserAgentParser.parse(userAgent);
        verify(deviceTrustService).trustDevice(user.getId(), deviceInfo.getSignature(), deviceInfo.getDeviceName());
    }

    private LoginRequest buildRequest() {
        LoginRequest request = new LoginRequest();
        request.setEmail("user@example.com");
        request.setPassword("Password123!");
        return request;
    }

    private User buildUser(boolean mfaEnabled) {
        User user = new User();
        user.setId(101L);
        user.setEmail("user@example.com");
        user.setFullName("Test User");
        user.setMfaEnabled(mfaEnabled);
        return user;
    }
}


//package com.pnm.auth.service.impl;
//
//import com.pnm.auth.domain.enums.AuditAction;
//import com.pnm.auth.dto.result.DeviceInfoResult;
//import com.pnm.auth.dto.request.LoginRequest;
//import com.pnm.auth.dto.request.MfaTokenVerifyRequest;
//import com.pnm.auth.dto.request.RefreshTokenRequest;
//import com.pnm.auth.dto.request.RegisterRequest;
//import com.pnm.auth.dto.response.AuthResponse;
//import com.pnm.auth.dto.response.UserIpLogResponse;
//import com.pnm.auth.domain.entity.MfaToken;
//import com.pnm.auth.domain.entity.RefreshToken;
//import com.pnm.auth.domain.entity.User;
//import com.pnm.auth.domain.enums.AuthProviderType;
//import com.pnm.auth.exception.custom.*;
//import com.pnm.auth.repository.*;
//import com.pnm.auth.util.JwtUtil;
//import com.pnm.auth.service.audit.AuditService;
//import com.pnm.auth.service.auth.VerificationService;
//import com.pnm.auth.service.email.EmailService;
//import com.pnm.auth.service.impl.auth.AuthServiceImpl;
//import com.pnm.auth.service.ipmonitoring.IpMonitoringService;
//import com.pnm.auth.service.login.LoginActivityService;
//import com.pnm.auth.service.login.SuspiciousLoginAlertService;
//import com.pnm.auth.util.UserAgentParser;
//import org.junit.jupiter.api.AfterEach;
//import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.Test;
//
//import org.junit.jupiter.api.extension.ExtendWith;
//import org.mockito.*;
//import org.mockito.junit.jupiter.MockitoExtension;
//import org.springframework.test.util.ReflectionTestUtils;
//
//import java.time.LocalDateTime;
//import java.util.Optional;
//
//import static org.assertj.core.api.Assertions.*;
//import static org.mockito.ArgumentMatchers.*;
//import static org.mockito.BDDMockito.*;
//
//@ExtendWith(MockitoExtension.class)
//class AuthServiceImplTest {
//
//    @InjectMocks
////    private AuthServiceImpl authService;
//
//    @Mock private UserRepository userRepository;
//    @Mock private VerificationService verificationService;
//    @Mock private EmailService emailService;
//    @Mock private JwtUtil jwtUtil;
//    @Mock private VerificationTokenRepository verificationTokenRepository;
//    @Mock private org.springframework.security.crypto.password.PasswordEncoder passwordEncoder;
//    @Mock private RefreshTokenRepository refreshTokenRepository;
//    @Mock private com.pnm.auth.util.BlacklistedTokenStore blacklistedTokenStore;
//    @Mock private MfaTokenRepository mfaTokenRepository;
//    @Mock private LoginActivityService loginActivityService;
//    @Mock private IpMonitoringService ipMonitoringService;
//    @Mock private SuspiciousLoginAlertService suspiciousLoginAlertService;
//    @Mock private AuditService auditService;
//
//    // allow mocking static UserAgentParser
//    private MockedStatic<UserAgentParser> userAgentParserStatic;
//
//    @BeforeEach
//    void setup() {
//        userAgentParserStatic = Mockito.mockStatic(UserAgentParser.class);
//        ReflectionTestUtils.setField(authService, "jwtRefreshExpirationMillis", 604800000L);
//    }
//
//    @AfterEach
//    void teardown() {
//        userAgentParserStatic.close();
//    }
//
//
//    //register
//    @Test
//    void register_emailAlreadyExists() {
//        RegisterRequest registerRequest = new RegisterRequest();
//        registerRequest.setFullName("anyName");
//        registerRequest.setEmail("abc@gmail.com");
//        registerRequest.setPassword("randomPass");
//
//        // Simulate user already exists
//        User user = new User();
//        user.setEmail(registerRequest.getEmail());
//
//        given(userRepository.findByEmail(registerRequest.getEmail()))
//                .willReturn(Optional.of(user));
//
//        // Act + Assert
//        assertThatThrownBy(() -> authService.register(registerRequest))
//                .isInstanceOf(UserAlreadyExistsException.class);
//    }
//
//    @Test
//    void register_success_shouldSendVerificationEmail() {
//
//        RegisterRequest registerRequest = new RegisterRequest();
//        registerRequest.setFullName("anyName");
//        registerRequest.setEmail("abc@gmail.com");
//        registerRequest.setPassword("randomPass");
//
//        // Mock email not existing
//        given(userRepository.findByEmail(registerRequest.getEmail()))
//                .willReturn(Optional.empty());
//
//        // Mock password encoder
//        given(passwordEncoder.encode("randomPass")).willReturn("encodedPass");
//
//        // Stub verification token
//        given(verificationService.createVerificationToken(any(User.class), eq("EMAIL_VERIFICATION")))
//                .willReturn("token123");
//
//        // Act
//        var response = authService.register(registerRequest);
//
//        // Verify user was saved with correct fields
//        then(userRepository).should().save(argThat(user ->
//                user.getEmail().equals("abc@gmail.com") &&
//                        user.getFullName().equals("anyName") &&
//                        user.getPassword().equals("encodedPass") &&
//                        user.getAuthProviderType() == AuthProviderType.EMAIL
//        ));
//
//        // Verify verification service call
//        then(verificationService).should().createVerificationToken(any(User.class), eq("EMAIL_VERIFICATION"));
//
//        // Verify email was sent
//        then(emailService).should().sendVerificationEmail("abc@gmail.com", "token123");
//
//        assertThat(response).isNotNull();
//    }
//
//
//    //login
//    @Test
//    void login_notFound_shouldThrowUserNotFoundException(){
//        String email = "abc@gmail.com";
//        String password = "randomPass";
//        String ip = "1.2.3.4";
//        String ua = "UA";
//
//        LoginRequest loginRequest = new LoginRequest();
//        loginRequest.setEmail(email);
//        loginRequest.setPassword(password);
//
//        given(userRepository.findByEmail(email)).willReturn(Optional.empty());
//
//        assertThatThrownBy(() -> authService.login(loginRequest, ip, ua)).isInstanceOf(UserNotFoundException.class);
//    }
//
//    @Test
//    void login_wrongPassword_shouldThrowInvalidCredentials_andRecordFailure() {
//        // Arrange
//        String email = "test2@example.com";
//        LoginRequest req = new LoginRequest();
//        req.setEmail(email);
//        req.setPassword("wrong");
//
//        User user = new User();
//        user.setId(11L);
//        user.setEmail(email);
//        user.setPassword("encoded");
//
//        given(userRepository.findByEmail(email)).willReturn(Optional.of(user));
//        given(passwordEncoder.matches(anyString(), anyString())).willReturn(false);
//
//        // Act & Assert
//        assertThatThrownBy(() -> authService.login(req, "1.2.3.4", "UA"))
//                .isInstanceOf(InvalidCredentialsException.class);
//
//        // verify loginActivityService.recordFailure called with email and message
//        then(loginActivityService).should().recordFailure(eq(user.getEmail()), contains("Wrong password"));
//        // ensure refresh token rotation did not happen
//        then(refreshTokenRepository).should(never()).invalidateAllForUser(user.getId());
//        then(refreshTokenRepository).should(never()).save(any(RefreshToken.class));
//    }
//
//    @Test
//    void login_blocked_shouldThrowAccountBlockedException(){
//        String email = "abc@gmail.com";
//        String password = "randomPass";
//        String ip = "1.2.3.4";
//        String ua = "UA";
//
//        LoginRequest loginRequest = new LoginRequest();
//        loginRequest.setEmail(email);
//        loginRequest.setPassword(password);
//
//        User user = new User();
//        user.setId(100L);
//        user.setEmail(email);
//        user.setPassword("encoded");
//        user.setAuthProviderType(null);
//        user.setEmailVerified(true);
//        user.setActive(false);
//        user.setMfaEnabled(false);
//
//        given(userRepository.findByEmail(email)).willReturn(Optional.of(user));
//        given(passwordEncoder.matches(anyString(), anyString())).willReturn(true);
//
//        assertThatThrownBy(()-> authService.login(loginRequest, ip, ua)).isInstanceOf(AccountBlockedException.class);
//
//        // ensure recordFailure called once (your login earlier may call recordFailure before throwing)
//        then(loginActivityService).should(times(1)).recordFailure(eq(user.getEmail()), anyString());
//    }
//
//    @Test
//    void login_emailNotVerified_shouldRecordFailureAndThrowException(){
//        String email = "abc@gmail.com";
//        String password = "randomPass";
//        String ip = "1.2.3.4";
//        String ua = "UA";
//
//        LoginRequest loginRequest = new LoginRequest();
//        loginRequest.setEmail(email);
//        loginRequest.setPassword(password);
//
//        User user = new User();
//        user.setId(100L);
//        user.setEmail(email);
//        user.setPassword("encoded");
//        user.setAuthProviderType(null);
//        user.setEmailVerified(false);
//        user.setActive(true);
//        user.setMfaEnabled(false);
//
//        given(userRepository.findByEmail(email)).willReturn(Optional.of(user));
//        given(passwordEncoder.matches(password, user.getPassword())).willReturn(true);
//
//        assertThatThrownBy(()->authService.login(loginRequest, ip, ua)).isInstanceOf(InvalidTokenException.class);
//        then(loginActivityService).should().recordFailure(eq(user.getEmail()), contains("verified"));
//    }
//
//    @Test
//    void login_mfaEnabled_shouldSendOtpViaEmail() {
//
//        String email = "abc@gmail.com";
//        String password = "randomPass";
//        String ip = "1.2.3.4";
//        String ua = "UA";
//
//        LoginRequest req = new LoginRequest();
//        req.setEmail(email);
//        req.setPassword(password);
//
//        User user = new User();
//        user.setId(10L);
//        user.setEmail(email);
//        user.setPassword("encodedPass");
//        user.setEmailVerified(true);
//        user.setActive(true);
//        user.setMfaEnabled(true);
//
//        given(userRepository.findByEmail(email)).willReturn(Optional.of(user));
//        given(passwordEncoder.matches(password, user.getPassword())).willReturn(true);
//
//        // FIX: Assign ID to the *same* MFA token object created inside service
//        given(mfaTokenRepository.save(any(MfaToken.class)))
//                .willAnswer(invocation -> {
//                    MfaToken passedToken = invocation.getArgument(0);
//                    passedToken.setId(999L);
//                    return passedToken;
//                });
//
//        // capture saved mfa token
//        ArgumentCaptor<MfaToken> captor = ArgumentCaptor.forClass(MfaToken.class);
//        ArgumentCaptor<AuthResponse> res = ArgumentCaptor.forClass(AuthResponse.class);
//
//        AuthResponse response = authService.login(req, ip, ua);
//
//        then(mfaTokenRepository).should().markAllUnusedTokensAsUsed(user.getId());
//        // verify a new MFA token was saved
//        then(mfaTokenRepository).should().save(captor.capture());
//        then(emailService).should().sendMfaOtpEmail(eq(email), anyString());
//        then(jwtUtil).shouldHaveNoInteractions();
//
//        assertThat(response.getType()).isEqualTo("MFA_REQUIRED");
//        assertThat(response.getMessage()).contains("verification");
//        assertThat(response.getMfaTokenId()).isEqualTo(999L);
//    }
//
//    @Test
//    void login_highRisk_shouldBlockLogin_andSendAlert() {
//        String email = "high@example.com";
//        String ip = "8.8.8.8";
//        String ua = "UA";
//
//        User user = new User();
//        user.setId(77L);
//        user.setEmail(email);
//        user.setPassword("encoded");
//        user.setEmailVerified(true);
//        user.setMfaEnabled(false);
//        user.setActive(true);
//
//        LoginRequest req = new LoginRequest();
//        req.setEmail(email);
//        req.setPassword("pw");
//
//        given(userRepository.findByEmail(email)).willReturn(Optional.of(user));
//        given(passwordEncoder.matches(anyString(), anyString())).willReturn(true);
//
//        UserIpLogResponse ipResp = new UserIpLogResponse();
//        ipResp.setRiskScore(85);
//        ipResp.setRiskReason("HIGH_RISK");
//        given(ipMonitoringService.recordLogin(user.getId(), ip, ua)).willReturn(ipResp);
//
//        // Act & Assert
//        assertThatThrownBy(() -> authService.login(req, ip, ua))
//                .isInstanceOf(HighRiskLoginException.class);
//
//        then(suspiciousLoginAlertService).should().sendHighRiskAlert(eq(user), eq(ip), eq(ua), anyList());
//        then(loginActivityService).should().recordFailure(eq(user.getEmail()), contains("High risk"));
//        then(jwtUtil).should(never()).generateAccessToken(any());
//        then(jwtUtil).should(never()).generateRefreshToken(any());
//        then(refreshTokenRepository).should(never()).save(any());
//
//    }
//
//    @Test
//    void login_mediumRisk_shouldCreateRiskOtpToken_andSendRiskOtpEmail() {
//        // Arrange
//        String email = "risk@example.com";
//        String ip = "5.6.7.8";
//        String ua = "UA";
//
//        User user = new User();
//        user.setId(55L);
//        user.setEmail(email);
//        user.setPassword("encoded");
//        user.setEmailVerified(true);
//        user.setMfaEnabled(false);
//        user.setActive(true);
//
//        LoginRequest req = new LoginRequest();
//        req.setEmail(email);
//        req.setPassword("pw");
//
//        given(userRepository.findByEmail(email)).willReturn(Optional.of(user));
//        given(passwordEncoder.matches(any(), any())).willReturn(true);
//
//        // ip monitoring returns medium risk
//        UserIpLogResponse ipResp = new UserIpLogResponse();
//        ipResp.setRiskScore(45);
//        ipResp.setRiskReason("SOME_REASON");
//        given(ipMonitoringService.recordLogin(user.getId(), ip, ua)).willReturn(ipResp);
//
//        ArgumentCaptor<MfaToken> captor = ArgumentCaptor.forClass(MfaToken.class);
//
//        // Act & Assert
//        assertThatThrownBy(() -> authService.login(req, ip, ua))
//                .isInstanceOf(RiskOtpRequiredException.class)
//                .satisfies(ex -> {
//                    // expecting RiskOtpRequiredException (or similar runtime) — we only assert it's runtime
//                    assertThat(ex).isNotNull();
//                });
//
//        // ensure OTP flow prepared: existing tokens marked and mfa token created
//        then(mfaTokenRepository).should().markAllUnusedTokensAsUsed(user.getId());
//        then(mfaTokenRepository).should().save(captor.capture());
//        MfaToken saved = captor.getValue();
//        assertThat(saved.isRiskBased()).isTrue();
//        then(jwtUtil).shouldHaveNoInteractions();
//        then(jwtUtil).should(never()).generateAccessToken(any());
//        then(emailService).should().sendMfaOtpEmail(eq(user.getEmail()), anyString());
//    }
//
//    @Test
//    void login_shouldSucceed_lowRisk_nonMfa() {
//        // Arrange
//        String email = "test@example.com";
//        String rawPassword = "password";
//        String ip = "1.2.3.4";
//        String ua = "UA";
//
//        User user = new User();
//        user.setId(100L);
//        user.setEmail(email);
//        user.setPassword("encoded");
//        user.setAuthProviderType(null);
//        user.setEmailVerified(true);
//        user.setActive(true);
//        user.setMfaEnabled(false);
//
//        LoginRequest req = new LoginRequest();
//        req.setEmail(email);
//        req.setPassword(rawPassword);
//
//        given(userRepository.findByEmail(email)).willReturn(Optional.of(user));
//        given(passwordEncoder.matches(rawPassword, user.getPassword())).willReturn(true);
//
//        // ip monitoring returns low risk
//        UserIpLogResponse ipResp = new UserIpLogResponse();
//        ipResp.setRiskScore(0);
//        ipResp.setRiskReason(null);
//        given(ipMonitoringService.recordLogin(user.getId(), ip, ua)).willReturn(ipResp);
//
//        given(jwtUtil.generateAccessToken(user)).willReturn("access-token");
//        given(jwtUtil.generateRefreshToken(user)).willReturn("refresh-token");
//
//        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
//
//        // Act
//        var response = authService.login(req, ip, ua);
//
//        // Assert - verify side effects
//        then(loginActivityService).should(times(2)).recordSuccess(user.getId(), user.getEmail());
//        then(refreshTokenRepository).should().invalidateAllForUser(user.getId());
//        then(refreshTokenRepository).should().save(captor.capture());
//
//        RefreshToken saved = captor.getValue();
//        assertThat(saved.getToken()).isEqualTo("refresh-token");
//        assertThat(saved.getUser().getId()).isEqualTo(user.getId());
//
//
//        // Response may hold tokens (structure varies). Assert access token present in AuthResponse getters if available.
//        assertThat(response).isNotNull();
//    }
//
//    //refreshToken
//    @Test
//    void refreshToken_reuseAttack_shouldInvalidateAndAudit() {
//        String oldToken = "reused";
//        RefreshToken stored = new RefreshToken();
//        stored.setId(2L);
//        stored.setToken(oldToken);
//        stored.setUsed(true);
//        stored.setInvalidated(false);
//        stored.setExpiresAt(LocalDateTime.now().plusDays(1));
//        User user = new User();
//        user.setId(300L);
//        stored.setUser(user);
//
//        given(refreshTokenRepository.findByToken(oldToken)).willReturn(Optional.of(stored));
//
//        RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest();
//        refreshTokenRequest.setRefreshToken(oldToken);
//
//        assertThatThrownBy(() -> authService.refreshToken(refreshTokenRequest))
//                .isInstanceOf(InvalidCredentialsException.class);
//
//        then(refreshTokenRepository).should().invalidateAllForUser(user.getId());
//        then(auditService).should().record(eq(AuditAction.REFRESH_TOKEN_REUSE),
//                eq(user.getId()), eq(user.getId()), contains("Refresh token reuse"), isNull(), isNull());
//    }
//
//    @Test
//    void refreshToken_success_shouldRotate() {
//        // Arrange
//        String oldToken = "old-token";
//        RefreshToken stored = new RefreshToken();
//        stored.setId(1L);
//        stored.setToken(oldToken);
//        stored.setUsed(false);
//        stored.setInvalidated(false);
//        stored.setExpiresAt(LocalDateTime.now().plusDays(1));
//        User user = new User();
//        user.setId(200L);
//        user.setEmail("rt@example.com");
//        stored.setUser(user);
//
//        given(refreshTokenRepository.findByToken(oldToken)).willReturn(Optional.of(stored));
//        given(jwtUtil.extractUsername(oldToken)).willReturn(user.getEmail());
//        given(jwtUtil.generateAccessToken(user)).willReturn("new-access");
//        given(jwtUtil.generateRefreshToken(user)).willReturn("new-refresh");
//
//        RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest();
//        refreshTokenRequest.setRefreshToken(oldToken);
//
//        // Act
//        var resp = authService.refreshToken(refreshTokenRequest);
//
//        // Assert
//        then(refreshTokenRepository).should().save(argThat((RefreshToken t) ->
//                t.getToken().equals("new-refresh") && t.getUser().getId().equals(user.getId())
//        ));
//        assertThat(resp).isNotNull();
//    }
//
//    //verifyOtp
//    @Test
//    void login_oauthUser_shouldThrowInvalidCredentials_andNotCheckPassword() {
//        // Arrange
//        String email = "oauth@example.com";
//        String ip = "1.1.1.1";
//        String ua = "UA";
//
//        User user = new User();
//        user.setId(10L);
//        user.setEmail(email);
//        user.setAuthProviderType(AuthProviderType.GOOGLE); // oauth provider
//        user.setPassword("irrelevant");
//        user.setEmailVerified(true);
//        user.setActive(true);
//        user.setMfaEnabled(false);
//
//        given(userRepository.findByEmail(email)).willReturn(Optional.of(user));
//
//        LoginRequest req = new LoginRequest();
//        req.setEmail(email);
//        req.setPassword("any");
//
//        // Act & Assert
//        assertThatThrownBy(() -> authService.login(req, ip, ua))
//                .isInstanceOf(InvalidCredentialsException.class);
//
//        // verify we did NOT call passwordEncoder.matches for oauth user
////        then(passwordEncoder).should(never()).matches(anyString(), anyString());
//        then(passwordEncoder).shouldHaveNoInteractions();
//        // ensure no tokens were created
//        then(jwtUtil).should(never()).generateAccessToken(any());
//        then(refreshTokenRepository).should(never()).save(any(RefreshToken.class));
//    }
//
//    @Test
//    void login_mfaEnabled_shouldSkipRiskLogic_andAlwaysSendOtp() {
//        String email = "mfaprio@example.com";
//        String ip = "10.10.10.10";
//        String ua = "UA";
//
//        User user = new User();
//        user.setId(100L);
//        user.setEmail(email);
//        user.setPassword("enc");
//        user.setEmailVerified(true);
//        user.setActive(true);
//        user.setMfaEnabled(true);
//
//        given(userRepository.findByEmail(email)).willReturn(Optional.of(user));
//        given(passwordEncoder.matches(anyString(), anyString())).willReturn(true);
//
//        LoginRequest req = new LoginRequest();
//        req.setEmail(email);
//        req.setPassword("pass");
//
//        var resp = authService.login(req, ip, ua);
//
//        // ipMonitoringService should not be called because MFA interrupts earlier
//        then(ipMonitoringService).should(never()).recordLogin(anyLong(), anyString(), anyString());
//
//        // mfa token saved and email sent
//        then(mfaTokenRepository).should().markAllUnusedTokensAsUsed(user.getId());
//        then(mfaTokenRepository).should().save(any(MfaToken.class));
//        then(emailService).should().sendMfaOtpEmail(eq(user.getEmail()), anyString());
//        assertThat(resp).isNotNull();
//    }
//
//    @Test
//    void verifyOtp_otpAlreadyUsed_shouldThrowInvalidTokenException() {
//
//        MfaTokenVerifyRequest req = new MfaTokenVerifyRequest();
//        req.setId(100L);
//        req.setOtp("000000");
//
//        String ip = "1.3.5";
//        String ua = "UA";
//
//        // Simulate USED token → repository returns empty
//        given(mfaTokenRepository.findByIdAndUsedFalse(req.getId()))
//                .willReturn(Optional.empty());
//
//        assertThatThrownBy(() -> authService.verifyOtp(req, ip, ua))
//                .isInstanceOf(InvalidTokenException.class);
//
//        then(loginActivityService)
//                .should()
//                .recordFailure(null, "OTP token not found or already used");
//    }
//
//    @Test
//    void verifyOtp_otpIsExpired_shouldThrowInvalidTokenException() {
//
//        MfaTokenVerifyRequest req = new MfaTokenVerifyRequest();
//        req.setId(100L);
//        req.setOtp("000000");
//
//        String ip = "1.4.2";
//        String ua = "UA";
//
//        User user = new User();
//        user.setId(10L);
//        user.setEmail("snds@mail.com");
//
//        MfaToken mfa = new MfaToken();
//        mfa.setId(100L);
//        mfa.setOtp("654321");
//        mfa.setUsed(false);
//        mfa.setUser(user);
//        mfa.setExpiresAt(LocalDateTime.now().minusMinutes(1));
//
//
//        // Simulate USED token → repository returns empty
//        given(mfaTokenRepository.findByIdAndUsedFalse(req.getId()))
//                .willReturn(Optional.of(mfa));
//
//        assertThatThrownBy(() -> authService.verifyOtp(req, ip, ua))
//                .isInstanceOf(InvalidTokenException.class);
//
//        then(loginActivityService).should().recordFailure(eq("snds@mail.com"), eq("OTP expired"));
//
//
//    }
//
//    @Test
//    void verifyOtp_wrongOtp_shouldThrowInvalidCredentials() {
//        long tokenId = 111L;
//        MfaToken mfa = new MfaToken();
//        mfa.setId(tokenId);
//        mfa.setOtp("654321");
//        mfa.setUsed(false);
//        mfa.setExpiresAt(LocalDateTime.now().plusMinutes(5));
//        User user = new User();
//        user.setId(600L);
//        user.setEmail("mfa2@example.com");
//        mfa.setUser(user);
//
//        given(mfaTokenRepository.findByIdAndUsedFalse(tokenId)).willReturn(Optional.of(mfa));
//
//        MfaTokenVerifyRequest req = new MfaTokenVerifyRequest();
//        req.setId(tokenId);
//        req.setOtp("000000");
//
//        assertThatThrownBy(() -> authService.verifyOtp(req, "1.2.3.4", "UA"))
//                .isInstanceOf(InvalidCredentialsException.class);
//
//        then(loginActivityService).should().recordFailure(user.getEmail(), "Wrong OTP entered");
//    }
//
//    @Test
//    void verifyOtp_success_mfa_shouldIssueTokens_andTrustDevice() {
//        // Arrange
//        long tokenId = 999L;
//        MfaToken mfa = new MfaToken();
//        mfa.setId(tokenId);
//        mfa.setOtp("123456");
//        mfa.setUsed(false);
//        mfa.setExpiresAt(LocalDateTime.now().plusMinutes(5));
//        User user = new User();
//        user.setId(500L);
//        user.setEmail("mfa@example.com");
//        mfa.setUser(user);
//        mfa.setRiskBased(false);
//
//        given(mfaTokenRepository.findByIdAndUsedFalse(tokenId)).willReturn(Optional.of(mfa));
//        given(mfaTokenRepository.save(any(MfaToken.class))).willAnswer(invocation -> invocation.getArgument(0));
//
//        // mock parser / device info
//        DeviceInfoResult dev = new DeviceInfoResult();
//        dev.setSignature("sig-1");
//        dev.setDeviceName("Chrome");
//        userAgentParserStatic.when(() -> UserAgentParser.parse(anyString())).thenReturn(dev);
//
//        given(jwtUtil.generateAccessToken(user)).willReturn("acc-1");
//        given(jwtUtil.generateRefreshToken(user)).willReturn("ref-1");
//
//        // Act
//        MfaTokenVerifyRequest req = new MfaTokenVerifyRequest();
//        req.setId(tokenId);
//        req.setOtp("123456");
//
//        var resp = authService.verifyOtp(req, "10.0.0.1", "UA-STRING");
//
//        // Assert
//        then(loginActivityService).should().recordSuccess(user.getId(), user.getEmail());
//        then(refreshTokenRepository).should().invalidateAllForUser(user.getId());
//        then(refreshTokenRepository).should().save(argThat((RefreshToken t) ->
//                t.getUser().getId().equals(user.getId()) && t.getToken().equals("ref-1")
//        ));
//
//        assertThat(resp).isNotNull();
//    }
//
//}

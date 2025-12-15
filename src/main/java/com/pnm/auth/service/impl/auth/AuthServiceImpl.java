//package com.pnm.auth.service.impl.auth;
//
//import com.pnm.auth.domain.entity.MfaToken;
//import com.pnm.auth.domain.entity.RefreshToken;
//import com.pnm.auth.domain.entity.User;
//import com.pnm.auth.domain.entity.VerificationToken;
//import com.pnm.auth.dto.result.DeviceInfoResult;
//import com.pnm.auth.dto.request.*;
//import com.pnm.auth.dto.response.AuthResponse;
//import com.pnm.auth.dto.response.UserDetailsResponse;
//import com.pnm.auth.dto.response.UserIpLogResponse;
//import com.pnm.auth.domain.enums.AuditAction;
//import com.pnm.auth.domain.enums.AuthProviderType;
//import com.pnm.auth.exception.custom.*;
//import com.pnm.auth.repository.*;
//import com.pnm.auth.util.JwtUtil;
//import com.pnm.auth.service.audit.AuditService;
//import com.pnm.auth.service.auth.AuthService;
//import com.pnm.auth.service.auth.VerificationService;
//import com.pnm.auth.service.device.TrustedDeviceService;
//import com.pnm.auth.service.email.EmailService;
//import com.pnm.auth.service.ipmonitoring.IpMonitoringService;
//import com.pnm.auth.service.login.LoginActivityService;
//import com.pnm.auth.service.login.SuspiciousLoginAlertService;
//import com.pnm.auth.util.Audit;
//import com.pnm.auth.util.BlacklistedTokenStore;
//import com.pnm.auth.util.UserAgentParser;
//import io.jsonwebtoken.Claims;
//import lombok.RequiredArgsConstructor;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.cache.annotation.CacheEvict;
//import org.springframework.cache.annotation.Cacheable;
//import org.springframework.cache.annotation.Caching;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.stereotype.Service;
//import org.springframework.transaction.annotation.Transactional;
//
//import java.security.SecureRandom;
//import java.time.LocalDateTime;
//import java.time.temporal.ChronoUnit;
//import java.util.Arrays;
//import java.util.List;
//
//@Service
//@RequiredArgsConstructor
//@Slf4j
//public class AuthServiceImpl implements AuthService {
//
//    private final UserRepository userRepository;
//    private final VerificationService verificationService;
//    private final EmailService emailService;
//    private final JwtUtil jwtUtil;
//    private final VerificationTokenRepository verificationTokenRepository;
//    private final PasswordEncoder passwordEncoder;
//    private final RefreshTokenRepository refreshTokenRepository;
//    private final BlacklistedTokenStore blacklistedTokenStore;
//    private final MfaTokenRepository mfaTokenRepository;
//    private final LoginActivityService loginActivityService;
//    private final IpMonitoringService ipMonitoringService;
//    private final SuspiciousLoginAlertService suspiciousLoginAlertService;
//    private final TrustedDeviceService trustedDeviceService;
//    private final AuditService auditService;
//
//    @Value("${jwt.refresh.expiration}")
//    private Long jwtRefreshExpirationMillis;
//
//    @Override
//    @Transactional
//    @CacheEvict(value = {"users.list"}, allEntries = true)
//    @Audit(action = AuditAction.USER_REGISTER, description = "User registration")
//    public AuthResponse register(RegisterRequest request) {
//
//        String email = request.getEmail().trim().toLowerCase();
//        log.info("AuthService.register(): started for email={}", email);
//
//        // Check if email already exists
//        if (userRepository.findByEmail(email).isPresent()) {
//            log.warn("AuthService.register(): failed, email={} already exists", email);
//            throw new UserAlreadyExistsException(
//                    "The email: " + email + " is already registered. Login using your email."
//            );
//        }
//
//        try {
//            // 1. Create and save new user
//            User user = new User();
//            user.setFullName(request.getFullName());
//            user.setEmail(email);
//            user.setPassword(passwordEncoder.encode(request.getPassword()));
//            user.setRoles(List.of("ROLE_USER"));
//            user.setAuthProviderType(AuthProviderType.EMAIL);
//
//            userRepository.save(user);
//            log.info("AuthService.register(): user saved email={}", email);
//
//            // 2. Create verification token
//            String token = verificationService.createVerificationToken(user, "EMAIL_VERIFICATION");
//
//            // 3. Send verification email
//            try {
//                emailService.sendVerificationEmail(user.getEmail(), token);
//                log.info("AuthService.register(): verification email sent to email={}", email);
//
//            } catch (EmailSendFailedException ex) {
//                // Already meaningful → pass through directly
//                throw ex;
//
//            } catch (Exception ex) {
//                log.error("AuthService.register(): verification email sending failed for email={}, message={}",
//                        email, ex.getMessage(), ex);
//
//                throw new EmailSendFailedException(
//                        "Failed to send verification email. Please try again later."
//                );
//            }
//
//            // 4. Success response
//            log.info("AuthService.register(): finished for email={}", email);
//            return new AuthResponse(
//                    "REGISTRATION_SUCCESSFUL",
//                    "Registration successful. Please verify email.",
//                    null,
//                    null,
//                    null
//            );
//
//        } catch (EmailSendFailedException ex) {
//            // Allow this to bubble to GlobalExceptionHandler
//            throw ex;
//
//        } catch (Exception ex) {
//            log.error("AuthService.register(): unexpected error for email={}, message={}",
//                    email, ex.getMessage(), ex);
//
//            throw new RegistrationFailedException(
//                    "Registration failed due to a server error. Please try again later."
//            );
//        }
//    }
//
//
//
//    @Override
//    @Transactional
//    @Audit(action = AuditAction.LOGIN_ATTEMPT, description = "User login attempt")
//    public AuthResponse login(LoginRequest request, String ip, String userAgent) {
//
//        String email = request.getEmail().trim().toLowerCase();
//        log.info("AuthService.login(): started for email={}", email);
//
//        // 1) USER EXISTS?
//        User user = userRepository.findByEmail(email)
//                .orElseThrow(() -> {
//                    log.warn("AuthService.login(): user not found email={}", email);
//                    return new UserNotFoundException("User not found with email: " + email);
//                });
//
//        // 2) DISALLOW PASSWORD LOGIN FOR OAUTH USERS
//        if (user.getAuthProviderType() != null && user.getAuthProviderType() != AuthProviderType.EMAIL) {
//            loginActivityService.recordFailure(email, "OAuth accounts cannot use password login");
//            log.warn("AuthService.login(): OAuth user attempted password login email={}", email);
//            throw new InvalidCredentialsException("OAuth users cannot login using password.");
//        }
//
//        // 3) INVALID PASSWORD?
//        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
//            loginActivityService.recordFailure(email, "Wrong password entered");
//            log.warn("AuthService.login(): wrong password email={}", email);
//            throw new InvalidCredentialsException("Wrong password. Please enter correct password.");
//        }
//
//        // 4) ACCOUNT BLOCKED?
//        if (!user.isActive()) {
//            loginActivityService.recordFailure(email, "Blocked user tried to login");
//            log.warn("AuthService.login(): blocked account login attempt email={}", email);
//            throw new AccountBlockedException("Your account has been blocked. Contact support.");
//        }
//
//        // 5) EMAIL VERIFIED?
//        if (!user.getEmailVerified()) {
//            loginActivityService.recordFailure(email, "Email not verified");
//            log.warn("AuthService.login(): email not verified email={}", email);
//            throw new InvalidTokenException("Verify your email to continue.");
//        }
//
//        // -----------------------------
//        // 2FA / MFA CHECK
//        // -----------------------------
//        if (user.isMfaEnabled()) {
//            log.info("AuthService.login(): MFA enabled for email={}", email);
//
//            try {
//                // Mark all old tokens as used
//                mfaTokenRepository.markAllUnusedTokensAsUsed(user.getId());
//
//                // 1. Generate 6-digit OTP
//                SecureRandom secureRandom = new SecureRandom();
//                String otp = String.format("%06d", secureRandom.nextInt(1_000_000));
//
//                // 2. Create MFA token entity
//                MfaToken mfaToken = new MfaToken();
//                mfaToken.setUser(user);
//                mfaToken.setOtp(otp);
//                mfaToken.setRiskBased(false);
//                mfaToken.setExpiresAt(LocalDateTime.now().plusMinutes(5));
//                mfaToken.setUsed(false);
//
//                mfaTokenRepository.save(mfaToken);
//
//                // 3. Send OTP email
//                emailService.sendMfaOtpEmail(user.getEmail(), otp);
//                log.info("AuthService.login(): MFA OTP generated for email={} (mfaTokenId={})", email, mfaToken.getId());
//
//
//                // 4. Return MFA_REQUIRED response
//                return new AuthResponse(
//                        "MFA_REQUIRED",
//                        "MFA verification required.",
//                        null,
//                        null,
//                        mfaToken.getId()
//                );
//
//            } catch (Exception ex) {
//                log.error("AuthService.login(): MFA OTP generation failed for email={}, message={}",
//                        email, ex.getMessage(), ex);
//                loginActivityService.recordFailure(email, "Failed to generate MFA OTP");
//                throw new OtpGenerationException("Unable to generate MFA OTP. Please try again later.");
//            }
//
//        }
//
//        // -------------------------
//        // RISK ENGINE (ONLY FOR NON-MFA USERS)
//        // -------------------------
//        UserIpLogResponse ipRisk = ipMonitoringService.recordLogin(user.getId(), ip, userAgent);
//        int risk = ipRisk.getRiskScore();
//
//        List<String> reasons = ipRisk.getRiskReason() != null
//                ? Arrays.asList(ipRisk.getRiskReason().split(","))
//                : List.of();
//
//        log.info("AuthService.login(): riskScore={} reasons={}", risk, reasons);
//
//        // HIGH RISK → BLOCK LOGIN
//        if (risk >= 80) {
//            log.error("AuthService.login(): HIGH RISK BLOCKED email={} score={}", email, risk);
//            suspiciousLoginAlertService.sendHighRiskAlert(user, ip, userAgent, reasons);
//            loginActivityService.recordFailure(email, "High risk login blocked");
//            throw new HighRiskLoginException("Login blocked due to high risk activity.");
//        }
//
//        // MEDIUM RISK → OTP REQUIRED (Use SAME OTP FLOW as MFA)
//        if (risk >= 40) {
//            log.warn("AuthService.login(): MEDIUM RISK OTP required email={} risk={}", email, risk);
//
//            try {
//                mfaTokenRepository.markAllUnusedTokensAsUsed(user.getId());
//
//                SecureRandom secureRandom = new SecureRandom();
//                String otp = String.format("%06d", secureRandom.nextInt(1_000_000));
//
//                MfaToken mfaToken = new MfaToken();
//                mfaToken.setUser(user);
//                mfaToken.setOtp(otp);
//                mfaToken.setRiskBased(true);
//                mfaToken.setExpiresAt(LocalDateTime.now().plusMinutes(5));
//                mfaToken.setUsed(false);
//
//                mfaTokenRepository.save(mfaToken);
//
//                emailService.sendMfaOtpEmail(user.getEmail(), otp);
//
//                throw new RiskOtpRequiredException(
//                        "Suspicious login detected. OTP verification required.",
//                        mfaToken.getId());
//
//                //for verifying opt we will use same controller for which we have used for verifying mfa otp i.e verifyMfaOtp()
//            } catch (Exception ex) {
//                log.error("AuthService.login(): Medium-risk OTP flow failed email={} msg={}", email, ex.getMessage(), ex);
//                loginActivityService.recordFailure(email, "Failed to send medium-risk OTP");
//                throw new EmailSendFailedException("Failed to send OTP. Please try again later.");
//            }
//        }
//        // =========================================================
//        // LOW RISK → SUCCESSFUL LOGIN FLOW
//        // =========================================================
//        try {
//
//            // 1. Invalidate all previous tokens for this user (important)
//            refreshTokenRepository.invalidateAllForUser(user.getId());
//
//            // 2. Generate new tokens
//            String newAccessToken = jwtUtil.generateAccessToken(user);
//            String newRefreshToken = jwtUtil.generateRefreshToken(user);
//
//            // 3. Save the new refresh token
//            RefreshToken newToken = new RefreshToken();
//            newToken.setToken(newRefreshToken);
//            newToken.setUser(user);
//            newToken.setCreatedAt(LocalDateTime.now());
//            newToken.setExpiresAt(LocalDateTime.now().plus(jwtRefreshExpirationMillis, ChronoUnit.MILLIS));
//            newToken.setUsed(false);
//            newToken.setInvalidated(false);
//
//            refreshTokenRepository.save(newToken);
//
//            // Record successful login
//            try {
//                loginActivityService.recordSuccess(user.getId(), user.getEmail());
//            } catch (Exception ex) {
//                log.error("AuthService.login(): failed to record login success for userId={}, message={}",
//                        user.getId(), ex.getMessage(), ex);
//            }
//
//
//            log.info("AuthService.login(): successful for email={} (refresh_token_saved)", email);
//            return new AuthResponse(
//                    "LOGIN_SUCCESS",
//                    "Login successful",
//                    newAccessToken,
//                    newRefreshToken,
//                    null);
//        }catch (Exception ex){
//            log.error("AuthService.login(): access and refresh tokens generation failed for email={}, message={}",
//                    email, ex.getMessage(), ex);
//            loginActivityService.recordFailure(email, "Failed to generate access and refresh tokens");
//            throw new TokenGenerationException("Login failed. Please try again later.");
//        }
//    }
//
//
//    @Audit(action = AuditAction.REFRESH_TOKEN_ROTATION, description = "Refreshing access token")
//    @Override
//    @Transactional
//    public AuthResponse refreshToken(RefreshTokenRequest refreshTokenRequest) {
//
//        String oldToken = refreshTokenRequest.getRefreshToken();
//        log.info("AuthService.refreshToken(): started (tokenPrefix={})", safeTokenPrefix(oldToken));
//
//        // 1) Find stored token
//        RefreshToken stored = refreshTokenRepository.findByToken(oldToken)
//                .orElseThrow(() -> {
//                    log.warn("AuthService.refreshToken(): invalid tokenPrefix={}", safeTokenPrefix(oldToken));
//                    return new InvalidTokenException("Invalid refresh token");
//                });
//
//        // 2) Expired or invalidated?
//        if (stored.isInvalidated() || stored.getExpiresAt().isBefore(LocalDateTime.now())) {
//            log.warn("AuthService.refreshToken(): expired/invalidated token used userId={}", stored.getUser().getId());
//            throw new InvalidTokenException("Refresh token expired");
//        }
//
//        // 3) Reuse Attack Protection
//        if (stored.isUsed()) {
//            log.error("AuthService.refreshToken(): REUSE DETECTED userId={} token={}",
//                    stored.getUser().getId(), safeTokenPrefix(oldToken));
//
//            refreshTokenRepository.invalidateAllForUser(stored.getUser().getId());
//
//            auditService.record(
//                    AuditAction.REFRESH_TOKEN_REUSE,
//                    stored.getUser().getId(),
//                    stored.getUser().getId(),
//                    "Refresh token reuse detected. All sessions invalidated.",
//                    null, null
//            );
//
//            throw new InvalidCredentialsException("Session compromised. Please login again.");
//        }
//
//        // 4) Extract email (MUST be outside try-catch)
//        String email;
//        try {
//            email = jwtUtil.extractUsername(oldToken);
//        } catch (Exception ex) {
//            log.warn("AuthService.refreshToken(): failed to extract email from tokenPrefix={}, msg={}",
//                    safeTokenPrefix(oldToken), ex.getMessage());
//            throw new InvalidTokenException("Invalid refresh token");
//        }
//
//        User user = stored.getUser();
//
//        // ======================================================
//        // TOKEN ROTATION
//        // ======================================================
//        try {
//            // Mark old token as used
//            stored.setUsed(true);
//            refreshTokenRepository.save(stored);
//
//            // Generate new tokens
//            String newAccessToken = jwtUtil.generateAccessToken(user);
//            String newRefreshToken = jwtUtil.generateRefreshToken(user);
//
//            RefreshToken newEntity = new RefreshToken();
//            newEntity.setToken(newRefreshToken);
//            newEntity.setUser(user);
//            newEntity.setCreatedAt(LocalDateTime.now());
//            newEntity.setExpiresAt(LocalDateTime.now().plus(jwtRefreshExpirationMillis, ChronoUnit.MILLIS));
//            newEntity.setUsed(false);
//            newEntity.setInvalidated(false);
//
//            refreshTokenRepository.save(newEntity);
//
//            // Record success (NON-critical)
//            try {
//                loginActivityService.recordSuccess(user.getId(), email);
//            } catch (Exception ex) {
//                log.error("AuthService.refreshToken(): Failed to record success userId={} msg={}",
//                        user.getId(), ex.getMessage());
//            }
//
//            log.info("AuthService.refreshToken(): rotation complete userId={}", user.getId());
//
//            return new AuthResponse(
//                    "TOKEN_REFRESHED",
//                    "Token refreshed successfully",
//                    newAccessToken,
//                    newRefreshToken,
//                    null
//            );
//
//        } catch (Exception ex) {
//            log.error("AuthService.refreshToken(): rotation failed email={} msg={}", email, ex.getMessage(), ex);
//            loginActivityService.recordFailure(email, "Failed to rotate refresh token");
//            throw new TokenGenerationException("Token refresh failed. Please login again.");
//        }
//    }
//
//
//
//    @Override
//    @Audit(action = AuditAction.PASSWORD_RESET_REQUEST, description = "Forgot password request")
//    public void forgotPassword(String rawEmail) {
//
//        String email = rawEmail.trim().toLowerCase();
//        log.info("AuthService.forgotPassword(): started for email={}", email);
//
//        // 1) Check user existence
//        User user = userRepository.findByEmail(email)
//                .orElseThrow(() -> {
//                    log.warn("AuthService.forgotPassword(): user not found email={}", email);
//                    return new UserNotFoundException("User not found with email: " + email);
//                });
//
//        try {
//            // 2) Create password reset token
//            String token = verificationService.createVerificationToken(user, "PASSWORD_RESET");
//
//            // 3) Send reset email (Resilience4j handles fallback)
//            emailService.sendPasswordResetEmail(user.getEmail(), token);
//
//            log.info("AuthService.forgotPassword(): reset email sent to email={}", email);
//
//        } catch (EmailSendFailedException ex) {
//            // Already meaningful → simply rethrow
//            throw ex;
//
//        } catch (Exception ex) {
//            log.error("AuthService.forgotPassword(): unexpected failure email={}, msg={}",
//                    email, ex.getMessage(), ex);
//
//            throw new EmailSendFailedException(
//                    "Unable to send password reset email. Please try again later."
//            );
//        }
//    }
//
//
//
//    @Override
//    @Transactional
//    @Audit(action = AuditAction.PASSWORD_RESET, description = "Password reset action")
//    public void resetPassword(ResetPasswordRequest request) {
//
//        String tokenPrefix = safeTokenPrefix(request.getToken());
//        log.info("AuthService.resetPassword() started (tokenPrefix={})", tokenPrefix);
//
//        // 1) Validate token existence
//        VerificationToken verificationToken = verificationTokenRepository.findByToken(request.getToken())
//                .orElseThrow(() -> {
//                    log.warn("AuthService.resetPassword(): invalid token (tokenPrefix={})", tokenPrefix);
//                    return new InvalidTokenException("Invalid token");
//                });
//
//        // 2) Check type
//        if (!"PASSWORD_RESET".equals(verificationToken.getType())) {
//            log.warn("AuthService.resetPassword(): token type mismatch (tokenPrefix={})", tokenPrefix);
//            throw new InvalidTokenException("Invalid token type");
//        }
//
//        // 3) Check expiration
//        if (verificationToken.getExpiresAt().isBefore(LocalDateTime.now())) {
//            log.warn("AuthService.resetPassword(): token expired (tokenPrefix={})", tokenPrefix);
//            throw new InvalidTokenException("Reset token has expired");
//        }
//
//        User user = verificationToken.getUser();
//
//        try {
//            // 4) Update password
//            user.setPassword(passwordEncoder.encode(request.getNewPassword()));
//            userRepository.save(user);
//
//            // 5) Delete token
//            verificationTokenRepository.delete(verificationToken);
//
//            // 6) Log success (optional)
//            try {
//                loginActivityService.recordSuccess(user.getId(), user.getEmail());
//            } catch (Exception ex) {
//                log.error("AuthService.resetPassword(): failed to record password reset success userId={} msg={}",
//                        user.getId(), ex.getMessage());
//            }
//
//            log.info("AuthService.resetPassword(): successful for userId={}", user.getId());
//
//        } catch (Exception ex) {
//            log.error("AuthService.resetPassword(): unexpected failure for userId={} msg={}",
//                    user.getId(), ex.getMessage(), ex);
//
//            throw new PasswordResetException(
//                    "Unable to reset password at the moment. Please try again later."
//            );
//        }
//    }
//
//
//
//    @Override
//    @Transactional(readOnly = true)
//    @Cacheable(value = "users", key = "#token")
//    public UserDetailsResponse userDetailsFromAccessToken(String token) {
//
//        log.info("AuthService.userDetailsFromAccessToken(): started");
//
//        // 1) Token missing
//        if (token == null || token.isBlank()) {
//            log.warn("AuthService.userDetailsFromAccessToken(): missing token");
//            throw new InvalidTokenException("Missing or invalid Authorization header");
//        }
//
//        // 2) Token expired
//        if (jwtUtil.isTokenExpired(token)) {
//            log.warn("AuthService.userDetailsFromAccessToken(): token expired");
//            throw new InvalidTokenException("Access token expired");
//        }
//
//        // 3) Extract email safely
//        String email;
//        try {
//            email = jwtUtil.extractUsername(token);
//        } catch (Exception ex) {
//            log.warn("AuthService.userDetailsFromAccessToken(): failed to extract email. msg={}", ex.getMessage());
//            throw new InvalidTokenException("Invalid access token");
//        }
//
//        log.info("AuthService.userDetailsFromAccessToken(): extracted email={}", email);
//
//        // 4) Load user
//        User user = userRepository.findByEmail(email)
//                .orElseThrow(() -> {
//                    log.warn("AuthService.userDetailsFromAccessToken(): user not found email={}", email);
//                    return new UserNotFoundException("User not found with email: " + email);
//                });
//
//        // 5) Blocked user?
//        if (!user.isActive()) {
//            log.warn("AuthService.userDetailsFromAccessToken(): blocked user requested details email={}", email);
//            throw new AccountBlockedException("Your account has been blocked. Contact support.");
//        }
//
//        // 6) SUCCESS RESPONSE
//        log.info("AuthService.userDetailsFromAccessToken(): success email={}", email);
//
//        return new UserDetailsResponse(
//                user.getFullName(),
//                user.getEmail(),
//                user.getRoles(),
//                user.getAuthProviderType(),
//                user.getCreatedAt(),
//                user.getUpdatedAt()
//        );
//    }
//
//
//
//    @Override
//    @Caching(evict = {
//            @CacheEvict(value = "users", key = "#accessToken"),   // FIXED SpEL
//            @CacheEvict(value = "users.list", allEntries = true)
//    })
//    @Audit(action = AuditAction.LOGOUT, description = "User logout")
//    public void logout(String accessToken, String refreshToken) {
//
//        log.info("AuthService.logout(): started");
//
//        if (accessToken == null || accessToken.isBlank()) {
//            log.warn("AuthService.logout(): missing access token");
//            throw new InvalidTokenException("Missing access token");
//        }
//
//        try {
//            // Extract claims safely
//            Claims claims = jwtUtil.extractAllClaims(accessToken);
//            long expiryMillis = claims.getExpiration().getTime();
//
//            // Blacklist access token until its natural expiry
//            blacklistedTokenStore.blacklistToken(accessToken, expiryMillis);
//            log.info("AuthService.logout(): access token blacklisted until={}", expiryMillis);
//
//        } catch (Exception ex) {
//            log.error("AuthService.logout(): failed to parse or blacklist token msg={}", ex.getMessage(), ex);
//            throw new InvalidTokenException("Invalid access token");
//        }
//
//        try {
//            // Delete refresh token
//            refreshTokenRepository.deleteByToken(refreshToken);
//            log.info("AuthService.logout(): refresh token deleted");
//        } catch (Exception ex) {
//            log.error("AuthService.logout(): failed to delete refresh token msg={}", ex.getMessage(), ex);
//            throw new LogoutFailedException("Logout failed due to a server error. Try again later.");
//        }
//
//        log.info("AuthService.logout(): finished");
//    }
//
//
//
//    @Override
//    @Transactional
//    @Caching(evict = {
//            @CacheEvict(value = "users", key = "#request.accessToken"),   // FIXED SPEL
//            @CacheEvict(value = "users.list", allEntries = true)
//    })
//    @Audit(action = AuditAction.OAUTH_LINK, description = "Linking OAuth account")
//    public void linkOAuthAccount(LinkOAuthRequest request) {
//
//        log.info("AuthService.linkOAuthAccount(): started provider={}", request.getProviderType());
//
//        String accessToken = request.getAccessToken();
//
//        if (accessToken == null || accessToken.isBlank()) {
//            log.warn("AuthService.linkOAuthAccount(): missing token");
//            throw new InvalidTokenException("Missing access token");
//        }
//
//        // Check expiry
//        if (jwtUtil.isTokenExpired(accessToken)) {
//            log.warn("AuthService.linkOAuthAccount(): token expired");
//            throw new InvalidTokenException("Access token expired");
//        }
//
//        // Extract email safely
//        String email;
//        try {
//            email = jwtUtil.extractUsername(accessToken);
//        } catch (Exception ex) {
//            log.warn("AuthService.linkOAuthAccount(): failed to parse token msg={}", ex.getMessage());
//            throw new InvalidTokenException("Invalid access token");
//        }
//
//        log.info("AuthService.linkOAuthAccount(): extracted email={}", email);
//
//        // Load user
//        User user = userRepository.findByEmail(email)
//                .orElseThrow(() -> {
//                    log.warn("AuthService.linkOAuthAccount(): user not found email={}", email);
//                    return new UserNotFoundException("User not found");
//                });
//
//        // Blocked user check
//        if (!user.isActive()) {
//            log.warn("AuthService.linkOAuthAccount(): blocked user attempted OAuth linking email={}", email);
//            throw new AccountBlockedException("Your account has been blocked. Contact support.");
//        }
//
//        // Provider conflict check
//        if (user.getAuthProviderType() != null &&
//                !user.getAuthProviderType().equals(request.getProviderType())) {
//
//            log.warn("AuthService.linkOAuthAccount(): provider conflict email={} existing={} new={}",
//                    email, user.getAuthProviderType(), request.getProviderType());
//
//            throw new UserAlreadyExistsException(
//                    "Account already linked with a different provider (" +
//                            user.getAuthProviderType() + ")."
//            );
//        }
//
//        // Save provider link
//        try {
//            user.setProviderId(request.getProviderId());
//            user.setAuthProviderType(request.getProviderType());
//            userRepository.save(user);
//
//            log.info("AuthService.linkOAuthAccount(): successfully linked provider={} for email={}",
//                    request.getProviderType(), email);
//
//        } catch (Exception ex) {
//            log.error("AuthService.linkOAuthAccount(): failed to save provider link email={} msg={}",
//                    email, ex.getMessage(), ex);
//
//            throw new OAuthLinkFailedException("Failed to link OAuth provider. Please try again later.");
//        }
//    }
//
//
//    @Override
//    @Transactional
//    @Caching(evict = {
//            @CacheEvict(value = "users", key = "#token"),        // FIXED SPEL
//            @CacheEvict(value = "users.list", allEntries = true)
//    })
//    @Audit(action = AuditAction.CHANGE_PASSWORD, description = "User password change")
//    public AuthResponse changePassword(String token, String oldPassword, String newPassword) {
//
//        log.info("AuthService.changePassword(): started");
//
//        // 1) Validate token
//        if (token == null || token.isBlank()) {
//            log.warn("AuthService.changePassword(): missing token");
//            throw new InvalidTokenException("Missing token");
//        }
//
//        if (jwtUtil.isTokenExpired(token)) {
//            log.warn("AuthService.changePassword(): token expired");
//            throw new InvalidTokenException("Token expired");
//        }
//
//        // 2) Extract email
//        String email;
//        try {
//            email = jwtUtil.extractUsername(token);
//        } catch (Exception ex) {
//            log.warn("AuthService.changePassword(): failed to parse token msg={}", ex.getMessage());
//            throw new InvalidTokenException("Invalid access token");
//        }
//
//        // 3) Load user
//        User user = userRepository.findByEmail(email)
//                .orElseThrow(() -> {
//                    log.warn("AuthService.changePassword(): user not found email={}", email);
//                    return new UserNotFoundException("User not found");
//                });
//
//        // 4) Blocked user?
//        if (!user.isActive()) {
//            log.warn("AuthService.changePassword(): blocked user tried to change password email={}", email);
//            throw new AccountBlockedException("Your account has been blocked.");
//        }
//
//        // 5) Validate old password
//        if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
//            log.warn("AuthService.changePassword(): old password mismatch email={}", email);
//            throw new InvalidCredentialsException("Old password is incorrect.");
//        }
//
//        // 6) OPTIONAL: Prevent same password
//        if (passwordEncoder.matches(newPassword, user.getPassword())) {
//            log.warn("AuthService.changePassword(): new password same as old email={}", email);
//            throw new InvalidCredentialsException("New password cannot be the same as old password.");
//        }
//
//        try {
//            // 7) Update password
//            user.setPassword(passwordEncoder.encode(newPassword));
//            userRepository.save(user);
//
//            // 8) Invalidate all refresh tokens
//            refreshTokenRepository.invalidateAllForUser(user.getId());
//            log.info("AuthService.changePassword(): invalidated all refresh tokens email={}", email);
//
//            // 9) Blacklist old access token
//            Claims claims = jwtUtil.extractAllClaims(token);
//            long expiryMillis = claims.getExpiration().getTime();
//            blacklistedTokenStore.blacklistToken(token, expiryMillis);
//            log.info("AuthService.changePassword(): blacklisted old access token email={}", email);
//
//            // 10) Generate new tokens
//            String newAccessToken = jwtUtil.generateAccessToken(user);
//            String newRefreshToken = jwtUtil.generateRefreshToken(user);
//
//            // 11) Save new refresh token
//            RefreshToken newEntity = new RefreshToken();
//            newEntity.setToken(newRefreshToken);
//            newEntity.setUser(user);
//            newEntity.setCreatedAt(LocalDateTime.now());
//            newEntity.setExpiresAt(LocalDateTime.now().plus(jwtRefreshExpirationMillis, ChronoUnit.MILLIS));
//            newEntity.setUsed(false);
//            newEntity.setInvalidated(false);
//            refreshTokenRepository.save(newEntity);
//
//            // 12) Record success
//            try {
//                loginActivityService.recordSuccess(user.getId(), email);
//            } catch (Exception ex) {
//                log.error("AuthService.changePassword(): failed to record success email={} msg={}", email, ex.getMessage());
//            }
//
//            log.info("AuthService.changePassword(): completed successfully email={}", email);
//
//            return new AuthResponse(
//                    "PASSWORD_CHANGED",
//                    "Password changed successfully",
//                    newAccessToken,
//                    newRefreshToken,
//                    null
//            );
//
//        } catch (Exception ex) {
//            log.error("AuthService.changePassword(): failed email={} msg={}", email, ex.getMessage(), ex);
//
//            loginActivityService.recordFailure(email, "Failed to change password");
//
//            throw new PasswordChangeException("Unable to change password. Try again later.");
//        }
//    }
//
//
//
//    @Override
//    @Transactional
//    @Audit(action = AuditAction.PROFILE_UPDATE, description = "User profile updated")
//    public UserDetailsResponse updateProfile(String token, UpdateProfileRequest request) {
//
//        // 1. Validate token
//        // 2. Extract email
//        // 3. Fetch user
//        // 4. Update fullName
//        // 5. Save user
//        // 6. Return UserDetailsResponse
//
//        return null;
//    }
//
//    @Override
//    @Audit(action = AuditAction.MFA_VERIFY, description = "User verifying MFA or risk-based OTP")
//    @Transactional
//    public AuthResponse verifyOtp(MfaTokenVerifyRequest request, String ip, String userAgent) {
//
//        log.info("AuthService.verifyOtp(): started for id={}", request.getId());
//
//        // 1) Fetch MFA token
//        MfaToken mfaToken = mfaTokenRepository.findByIdAndUsedFalse(request.getId())
//                .orElseThrow(() -> {
//                    loginActivityService.recordFailure(null, "OTP token not found or already used");
//                    log.warn("AuthService.verifyOtp(): token not found id={}", request.getId());
//                    return new InvalidTokenException("OTP token not found or already used");
//                });
//
//        // 2) Check expiration
//        if (mfaToken.getExpiresAt().isBefore(LocalDateTime.now())) {
//            loginActivityService.recordFailure(mfaToken.getUser().getEmail(), "OTP expired");
//            log.warn("AuthService.verifyOtp(): token expired id={}", request.getId());
//            throw new InvalidTokenException("OTP expired");
//        }
//
//        // 3) Check OTP value
//        if (!mfaToken.getOtp().equals(request.getOtp().trim())) {
//            loginActivityService.recordFailure(mfaToken.getUser().getEmail(), "Wrong OTP entered");
//            log.warn("AuthService.verifyOtp(): wrong OTP for id={}", request.getId());
//            throw new InvalidCredentialsException("Wrong OTP");
//        }
//
//        // 4) Mark token as used
//        try {
//            mfaToken.setUsed(true);
//            mfaTokenRepository.save(mfaToken);
//        } catch (Exception ex) {
//            log.error("AuthService.verifyOtp(): failed marking token used id={} msg={}",
//                    request.getId(), ex.getMessage(), ex);
//            throw new OtpVerificationException("Failed verifying OTP. Try again.");
//        }
//
//        // 5) Fetch user
//        User user = mfaToken.getUser();
//
//        // ✔ Blocked user check
//        if (!user.isActive()) {
//            log.warn("AuthService.verifyOtp(): blocked user tried to verify OTP email={}", user.getEmail());
//            throw new AccountBlockedException("Your account has been blocked.");
//        }
//
//        // 6) Record success login
//        try {
//            loginActivityService.recordSuccess(user.getId(), user.getEmail());
//        } catch (Exception ex) {
//            log.warn("AuthService.verifyOtp(): failed to record login success userId={}", user.getId());
//        }
//
//        // 7) Save trusted device
//        try {
//            DeviceInfoResult deviceInfoResult = UserAgentParser.parse(userAgent);
//            trustedDeviceService.trustDevice(
//                    user.getId(),
//                    deviceInfoResult.getSignature(),
//                    deviceInfoResult.getDeviceName()
//            );
//        } catch (Exception ex) {
//            log.warn("AuthService.verifyOtp(): failed to save trusted device userId={} msg={}",
//                    user.getId(), ex.getMessage());
//        }
//
//        try {
//            // 8) Invalidate all old tokens
//            refreshTokenRepository.invalidateAllForUser(user.getId());
//
//            // 9) Create new tokens
//            String newAccessToken = jwtUtil.generateAccessToken(user);
//            String newRefreshToken = jwtUtil.generateRefreshToken(user);
//
//            RefreshToken newToken = new RefreshToken();
//            newToken.setToken(newRefreshToken);
//            newToken.setUser(user);
//            newToken.setCreatedAt(LocalDateTime.now());
//            newToken.setExpiresAt(LocalDateTime.now().plus(jwtRefreshExpirationMillis, ChronoUnit.MILLIS));
//            newToken.setUsed(false);
//            newToken.setInvalidated(false);
//
//            refreshTokenRepository.save(newToken);
//
//            // 10) Record risk data
//            try {
//                ipMonitoringService.recordLogin(user.getId(), ip, userAgent);
//            } catch (Exception ex) {
//                log.warn("AuthService.verifyOtp(): ipMonitoring failed userId={} msg={}",
//                        user.getId(), ex.getMessage());
//            }
//
//            log.info("AuthService.verifyOtp(): completed email={}", user.getEmail());
//
//            String message = mfaToken.isRiskBased()
//                    ? "Risk-based OTP verified successfully"
//                    : "MFA OTP verified successfully";
//
//            String type = mfaToken.isRiskBased()
//                    ? "RISK_VERIFIED"
//                    : "MFA_VERIFIED";
//
//            return new AuthResponse(
//                    type,
//                    message,
//                    newAccessToken,
//                    newRefreshToken,
//                    null
//            );
//
//        } catch (Exception ex) {
//            log.error("AuthService.verifyOtp(): failed generating new tokens msg={}", ex.getMessage(), ex);
//            loginActivityService.recordFailure(user.getEmail(), "Failed generating new tokens post-OTP");
//            throw new TokenGenerationException("Unable to complete verification. Try again.");
//        }
//    }
//
//
//    // Helper to avoid StringIndexOutOfBounds if token is short/null
//    private String safeTokenPrefix(String token) {
//        if (token == null) return "null";
//        return token.length() <= 10 ? token : token.substring(0, 10);
//    }
//
//}
//

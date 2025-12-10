package com.pnm.auth.service.impl;

import com.pnm.auth.dto.DeviceInfo;
import com.pnm.auth.dto.request.*;
import com.pnm.auth.dto.response.AuthResponse;
import com.pnm.auth.dto.response.UserDetailsResponse;
import com.pnm.auth.dto.response.UserIpLogResponse;
import com.pnm.auth.entity.*;
import com.pnm.auth.enums.AuditAction;
import com.pnm.auth.enums.AuthProviderType;
import com.pnm.auth.exception.*;
import com.pnm.auth.repository.*;
import com.pnm.auth.service.*;
import com.pnm.auth.security.JwtUtil;
import com.pnm.auth.util.Audit;
import com.pnm.auth.util.BlacklistedTokenStore;
import com.pnm.auth.util.UserAgentParser;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.Caching;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final VerificationService verificationService;
    private final EmailService emailService;
    private final JwtUtil jwtUtil;
    private final VerificationTokenRepository verificationTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenRepository refreshTokenRepository;
    private final BlacklistedTokenStore blacklistedTokenStore;
    private final MfaTokenRepository mfaTokenRepository;
    private final LoginActivityService loginActivityService;
    private final IpMonitoringService ipMonitoringService;
    private final SuspiciousLoginAlertService suspiciousLoginAlertService;
    private final TrustedDeviceService trustedDeviceService;
    private final AuditService auditService;

    @Value("${jwt.refresh.expiration}")
    private Long jwtRefreshExpirationMillis;

    @Override
    @Transactional
    @CacheEvict(value = {"users.list"}, allEntries = true)
    @Audit(action = AuditAction.USER_REGISTER, description = "User registration")
    public AuthResponse register(RegisterRequest request) {

        String email = request.getEmail().trim().toLowerCase();
        log.info("AuthService.register(): started for email={}", email);

        if (userRepository.findByEmail(email).isPresent()) {
            log.warn("AuthService.register(): failed, email={} already exists", email);
            throw new UserAlreadyExistsException("The email: " + email + " is already registered. Login using your email");
        }
            User user = new User();

            user.setFullName(request.getFullName());
            user.setEmail(email);
            user.setPassword(passwordEncoder.encode(request.getPassword()));
            user.setRoles(List.of("ROLE_USER"));
            user.setAuthProviderType(AuthProviderType.EMAIL);
            userRepository.save(user);
            log.info("AuthService.register(): user saved email={}", email);

            //Creating verification token
            String token = verificationService.createVerificationToken(user, "EMAIL_VERIFICATION");

            //Sending email to user with verification link
            emailService.sendVerificationEmail(user.getEmail(), token);
            log.info("AuthService.register(): verification email sent to email={}", email);
            log.info("AuthService.register(): finished for email={}", email);
            return new AuthResponse(
                    "REGISTRATION_SUCCESSFUL",
                    "Registration successful. Please verify email.",
                    null,
                    null,
                    null);
    }


    @Override
    @Transactional
    @Audit(action = AuditAction.LOGIN_ATTEMPT, description = "User login attempt")
    public AuthResponse login(LoginRequest request, String ip, String userAgent) {
        String email = request.getEmail().trim().toLowerCase();
        log.info("AuthService.login(): started for email={}", email);
        //Check user in db
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("AuthService.login(): user not found with email={}", email);
                    return new UserNotFoundException("User not found with email: " + email);
                });

        //Check password matches or not
        if(!passwordEncoder.matches(request.getPassword(), user.getPassword())){
            //Record activity for wrong password
            loginActivityService.recordFailure(user.getEmail(), "Wrong password entered");
            log.warn("AuthService.login(): incorrect password for email={}", email);
            throw new InvalidCredentialsException("Wrong password. Please enter correct password");
        }

        if (!user.isActive()) {
            log.warn("AuthService.login(): Blocked user trying to login for email={}", email);
            throw new AccountBlockedException("Your account has been blocked. Contact support.");
        }

        //Check email is verified or not
        if(!user.getEmailVerified()){
            log.warn("AuthService.login(): email not verified email={}", email);
            throw new InvalidTokenException("Verify email first");
        }

        loginActivityService.recordSuccess(user.getId(), user.getEmail());

        // -----------------------------
        // 2FA / MFA CHECK
        // -----------------------------
        if (user.isMfaEnabled()) {
            log.info("AuthService.login(): MFA enabled for email={}", email);

            mfaTokenRepository.markAllUnusedTokensAsUsed(user.getId());

            // 1. Generate 6-digit OTP
            SecureRandom secureRandom = new SecureRandom();
            String otp = String.format("%06d", secureRandom.nextInt(1_000_000));

            // 2. Create MFA token entity
            MfaToken mfaToken = new MfaToken();
            mfaToken.setUser(user);
            mfaToken.setOtp(otp);
            mfaToken.setRiskBased(false);
            mfaToken.setExpiresAt(LocalDateTime.now().plusMinutes(5));
            mfaToken.setUsed(false);

            mfaTokenRepository.save(mfaToken);

            // 3. Send OTP email
            emailService.sendMfaOtpEmail(user.getEmail(), otp);
            log.info("AuthService.login(): MFA OTP generated for email={} (mfaTokenId={})", email, mfaToken.getId());

            // 4. Return MFA_REQUIRED response
            return new AuthResponse(
                    "MFA_REQUIRED",
                    "MFA verification required.",
                    null,
                    null,
                    mfaToken.getId()   // <--- IMPORTANT: pass MFA token ID
            );
        }

        // -------------------------
        // 4) RISK ENGINE (ONLY FOR NON-MFA USERS)
        // -------------------------
        UserIpLogResponse ipRisk = ipMonitoringService.recordLogin(user.getId(), ip, userAgent);

        int risk = ipRisk.getRiskScore();
        List<String> reasons = ipRisk.getRiskReason() != null
                ? Arrays.asList(ipRisk.getRiskReason().split(","))
                : List.of();

        log.info("AuthService.login(): riskScore={} reasons={}", risk, reasons);

        // -------------------------
        // HIGH RISK → BLOCK LOGIN
        // -------------------------
        if (risk >= 80) {
            log.error("HIGH RISK BLOCKED for email={} riskScore={}", email, risk);
            suspiciousLoginAlertService.sendHighRiskAlert(user, ip, userAgent, reasons);
            loginActivityService.recordFailure(email, "High risk login blocked");
            throw new HighRiskLoginException("Login blocked due to high risk activity.");
        }

        // -------------------------
        // MEDIUM RISK → OTP REQUIRED (Use SAME OTP FLOW as MFA)
        // -------------------------
        if (risk >= 40) {
            log.warn("MEDIUM RISK login, OTP required email={} risk={}", email, risk);

            mfaTokenRepository.markAllUnusedTokensAsUsed(user.getId());

            SecureRandom secureRandom = new SecureRandom();
            String otp = String.format("%06d", secureRandom.nextInt(1_000_000));

            MfaToken mfaToken = new MfaToken();
            mfaToken.setUser(user);
            mfaToken.setOtp(otp);
            mfaToken.setRiskBased(true);
            mfaToken.setExpiresAt(LocalDateTime.now().plusMinutes(5));
            mfaToken.setUsed(false);
            mfaTokenRepository.save(mfaToken);

            emailService.sendMfaOtpEmail(user.getEmail(), otp);

            throw new RiskOtpRequiredException(
                    "Suspicious login detected. OTP verification required.",
                    mfaToken.getId());

            //for verifying opt we will use same controller for which we have used for verifying mfa otp i.e verifyMfaOtp()
        }

        //else low risk - generate tokens

        // 1. Invalidate all previous tokens for this user (important)
        refreshTokenRepository.invalidateAllForUser(user.getId());

        // 2. Generate new tokens
        String newAccessToken = jwtUtil.generateAccessToken(user);
        String newRefreshToken = jwtUtil.generateRefreshToken(user);

        // 3. Save the new refresh token
        RefreshToken newToken = new RefreshToken();
        newToken.setToken(newRefreshToken);
        newToken.setUser(user);
        newToken.setCreatedAt(LocalDateTime.now());
        newToken.setExpiresAt(LocalDateTime.now().plus(jwtRefreshExpirationMillis, ChronoUnit.MILLIS));
        newToken.setUsed(false);
        newToken.setInvalidated(false);

        refreshTokenRepository.save(newToken);

        // Record successful login
        loginActivityService.recordSuccess(user.getId(), user.getEmail());

        log.info("AuthService.login(): successful for email={} (refresh_token_saved)", email);
        return new AuthResponse(
                "LOGIN_SUCCESS",
                "Login successful",
                newAccessToken,
                newRefreshToken,
                null);
    }


    @Audit(action = AuditAction.REFRESH_TOKEN_ROTATION, description = "Refreshing access token")
    @Override
    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest refreshTokenRequest) {

        String oldToken = refreshTokenRequest.getRefreshToken();
        log.info("AuthService.refreshToken(): started (tokenPrefix={})", safeTokenPrefix(oldToken));

        RefreshToken stored = refreshTokenRepository.findByToken(oldToken)
                .orElseThrow(() -> {
                    log.warn("AuthService.refreshToken(): invalid tokenPrefix={}", safeTokenPrefix(oldToken));
                    return new InvalidTokenException("Invalid refresh token");
                });

        // 1) Check expired or invalidated
        if (stored.isInvalidated() || stored.getExpiresAt().isBefore(LocalDateTime.now())) {
            log.warn("Expired or invalidated refresh token used userId={}", stored.getUser().getId());
            throw new InvalidTokenException("Refresh token expired");
        }

        // 2) Check REUSE ATTACK
        if (stored.isUsed()) {
            log.error("REFRESH TOKEN REUSE DETECTED userId={} token={}", stored.getUser().getId(), safeTokenPrefix(oldToken));

            // Invalidate all tokens for user
            refreshTokenRepository.invalidateAllForUser(stored.getUser().getId());

            auditService.record(
                    AuditAction.REFRESH_TOKEN_REUSE,
                    stored.getUser().getId(),
                    stored.getUser().getId(),
                    "Refresh token reuse detected. All sessions invalidated.",
                    null,null
            );

            throw new InvalidCredentialsException("Session compromised. Please login again.");
        }

        // 3) Mark this token as used
        stored.setUsed(true);
        refreshTokenRepository.save(stored);

        String email = jwtUtil.extractUsername(oldToken);
        User user = stored.getUser();

        // 4) Issue new tokens
        String newAccessToken = jwtUtil.generateAccessToken(user);
        String newRefreshToken = jwtUtil.generateRefreshToken(user);

        RefreshToken newEntity = new RefreshToken();
        newEntity.setToken(newRefreshToken);
        newEntity.setUser(user);
        newEntity.setCreatedAt(LocalDateTime.now());
        newEntity.setExpiresAt(LocalDateTime.now().plus(jwtRefreshExpirationMillis, ChronoUnit.MILLIS));
        newEntity.setUsed(false);
        newEntity.setInvalidated(false);

        refreshTokenRepository.save(newEntity);

        log.info("AuthService.refreshToken(): rotation complete for userId={}", user.getId());

        return new AuthResponse(
                "TOKEN_REFRESHED",
                "Token refreshed successfully",
                newAccessToken,
                newRefreshToken,
                null
        );
    }



    @Override
    @Audit(action = AuditAction.PASSWORD_RESET_REQUEST, description = "Forgot password request")
    public void forgotPassword(String rawEmail) {

        String email = rawEmail.trim().toLowerCase();
        log.info("AuthService.forgotPassword(): started for email={}", email);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("AuthService.forgotPassword(): user not found email={}", email);
                    return new UserNotFoundException("User not found with email: " + email);
                });
        String token = verificationService.createVerificationToken(user, "PASSWORD_RESET");
        emailService.sendPasswordResetEmail(user.getEmail(), token);

        log.info("AuthService.forgotPassword(): reset email sent to email={}", email);
    }


    @Override
    @Transactional
    @Audit(action = AuditAction.PASSWORD_RESET, description = "Password reset action")
    public void resetPassword(ResetPasswordRequest request) {

        log.info("AuthService.resetPassword() started");

        // Validate token
        VerificationToken verificationToken = verificationTokenRepository.findByToken(request.getToken())
                .orElseThrow(() -> {
                    log.warn("AuthService.resetPassword(): invalid token");
                    return new InvalidTokenException("Invalid token");
                });

        // Check type
        if (!verificationToken.getType().equals("PASSWORD_RESET")){
            log.warn("AuthService.resetPassword(): token type mismatch");
            throw new InvalidTokenException("Token type mismatch");
        }

        // Check expiration
        if (verificationToken.getExpiresAt().isBefore(LocalDateTime.now())){
            log.warn("AuthService.resetPassword(): token expired");
            throw new InvalidTokenException("Token expired");
        }

        // Load user from DB
        User user = verificationToken.getUser();
        // Encode new password
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        // Save updated user
        userRepository.save(user);

        // Delete token after use (important)
        verificationTokenRepository.delete(verificationToken);

        log.info("AuthService.resetPassword(): successful for userId={}", user.getId());
    }


    @Override
    @Transactional(readOnly = true)
    @Cacheable(value = "users", key = "@jwtUtil.extractUsername(#token)")
    public UserDetailsResponse userDetailsFromAccessToken(String token) {

        log.info("AuthService.userDetailsFromAccessToken(): started");

        if (token == null) {
            log.warn("AuthService.userDetailsFromAccessToken(): missing Authorization header");
            throw new InvalidTokenException("Missing or invalid Authorization header");
        }

        // Check expiration
        if (jwtUtil.isTokenExpired(token)) {
            log.warn("AuthService.userDetailsFromAccessToken(): token expired");
            throw new InvalidTokenException("Access token expired");
        }

        // Extract email from access token
        String email = jwtUtil.extractUsername(token);
        log.info("AuthService.userDetailsFromAccessToken(): extracted email={}", email);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("AuthService.userDetailsFromAccessToken(): user not found email={}", email);
                    return new UserNotFoundException("User not found with email: " + email);
                });

        log.info("AuthService.userDetailsFromAccessToken(): success email={}", email);

        return new UserDetailsResponse(
                user.getFullName(),
                user.getEmail(),
                user.getRoles(),
                user.getAuthProviderType(),
                user.getCreatedAt(),
                user.getUpdatedAt()
        );
    }


    @Override
    @Caching(evict = {
            @CacheEvict(value = "users", key = "@jwtUtil.extractUsername(#accessToken)"),
            @CacheEvict(value = "users.list", allEntries = true)
    })
    @Audit(action = AuditAction.LOGOUT, description = "User logout")
    public void logout(String accessToken, String refreshToken) {

        log.info("AuthService.logout(): started");

        // Extract access token expiry
        Claims claims = jwtUtil.extractAllClaims(accessToken);
        long expiry = claims.getExpiration().getTime();

        // Blacklist access token UNTIL it expires
        blacklistedTokenStore.blacklistToken(accessToken, expiry);
        log.info("AuthService.logout(): Access token blacklisted until={}", expiry);

        // Delete refresh token from DB
        refreshTokenRepository.deleteByToken(refreshToken);
        log.info("AuthService.logout(): Refresh token deleted");

        log.info("AuthService.logout(): finished");
    }


    @Override
    @Transactional
    @Caching(evict = {
            @CacheEvict(value = "users", key = "@jwtUtil.extractUsername(#request.accessToken)"),
            @CacheEvict(value = "users.list", allEntries = true)
    })
    @Audit(action = AuditAction.OAUTH_LINK, description = "Linking OAuth account")
    public void linkOAuthAccount(LinkOAuthRequest request) {

        log.info("AuthService.linkOAuthAccount(): started provider={}", request.getProviderType());

        String token = request.getAccessToken();

        if (jwtUtil.isTokenExpired(token)) {
            log.warn("AuthService.linkOAuthAccount(): token expired");
            throw new InvalidTokenException("Token expired");
        }

        String email = jwtUtil.extractUsername(token);
        log.info("AuthService.linkOAuthAccount(): extracted email={}", email);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("AuthService.linkOAuthAccount(): user not found email={}", email);
                    return new UserNotFoundException("User not found");
                });

        // If already linked with another provider
        if (user.getProviderId() != null &&
                user.getAuthProviderType() != null &&
                !user.getProviderId().equals(request.getProviderId())) {
            log.warn("AuthService.linkOAuthAccount(): provider conflict for email={}", email);
            throw new UserAlreadyExistsException("This account is already linked with another provider");
        }

        // Link the provider
        user.setProviderId(request.getProviderId());
        user.setAuthProviderType(request.getProviderType());

        userRepository.save(user);

        log.info("AuthService.linkOAuthAccount(): successfully linked provider={} for email={}",
                request.getProviderType(), email);
    }

    @Override
    @Transactional
    @Caching(evict = {
            @CacheEvict(value = "users", key = "@jwtUtil.extractUsername(#token)"),
            @CacheEvict(value = "users.list", allEntries = true)
    })
    @Audit(action = AuditAction.CHANGE_PASSWORD, description = "User password change")
    public AuthResponse changePassword(String token, String oldPassword, String newPassword) {

        if (jwtUtil.isTokenExpired(token)) {
            log.warn("AuthService.changePassword(): token expired");
            throw new InvalidTokenException("Token expired");
        }

            String email = jwtUtil.extractUsername(token);
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> {
                        log.warn("AuthService.changePassword(): user not found email={}", email);
                        return new UserNotFoundException("User not found with email: " + email);
                    });

            if (!passwordEncoder.matches(oldPassword, user.getPassword())){
                log.warn("AuthService.changePassword(): old password mismatch for email={}", email);
                throw new InvalidCredentialsException("Old password is wrong enter correct password");
            }

            user.setPassword(passwordEncoder.encode(newPassword));
            userRepository.save(user);
            log.info("AuthService.changePassword(): password updated for email={}", email);


        // Delete all old refresh tokens
        refreshTokenRepository.deleteAllByUserId(user.getId());
        log.info("AuthService.changePassword(): deleted all old refresh tokens for email={}", email);


        // Blacklist old access token
        Claims claims = jwtUtil.extractAllClaims(token);
        long expiry = claims.getExpiration().getTime();
        blacklistedTokenStore.blacklistToken(token, expiry);
        log.info("AuthService.changePassword(): Access token blacklisted until={} for email={}", expiry, email);

        // 1. Invalidate all previous tokens for this user (important)
        refreshTokenRepository.invalidateAllForUser(user.getId());

        // Create new tokens
        String newAccessToken = jwtUtil.generateAccessToken(user);
        String newRefreshToken = jwtUtil.generateRefreshToken(user);
        log.info("AuthService.changePassword(): created new accessToken and refreshToken for email={}",email);

        // Save refresh token to DB
        RefreshToken newToken = new RefreshToken();
        newToken.setToken(newRefreshToken);
        newToken.setUser(user);
        newToken.setCreatedAt(LocalDateTime.now());
        newToken.setExpiresAt(LocalDateTime.now().plus(jwtRefreshExpirationMillis, ChronoUnit.MILLIS));
        newToken.setUsed(false);
        newToken.setInvalidated(false);

        refreshTokenRepository.save(newToken);

        log.info("AuthService.changePassword(): completed successfully for email={}", email);
        return new AuthResponse(
                "PASSWORD_CHANGED",
                "Password changed successfully",
                newAccessToken,
                newRefreshToken,
                null);
    }


    @Override
    @Transactional
    @Audit(action = AuditAction.PROFILE_UPDATE, description = "User profile updated")
    public UserDetailsResponse updateProfile(String token, UpdateProfileRequest request) {

        // 1. Validate token
        // 2. Extract email
        // 3. Fetch user
        // 4. Update fullName
        // 5. Save user
        // 6. Return UserDetailsResponse

        return null;
    }

    @Override
    @Audit(action = AuditAction.MFA_VERIFY, description = "User verifying MFA or risk-based OTP")
    public AuthResponse verifyOtp(MfaTokenVerifyRequest request, String ip, String userAgent) {

        log.info("AuthService.verifyOtp(): started for id={}", request.getId());

        // Fetch token
        MfaToken mfaToken = mfaTokenRepository.findByIdAndUsedFalse(request.getId())
                .orElseThrow(() -> {
                    loginActivityService.recordFailure(null, "OTP token not found or already used");
                    log.warn("AuthService.verifyOtp(): MfaToken not found for id={}", request.getId());
                    return new InvalidTokenException("Token not found");
                });

        // check expiry
        if (mfaToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            loginActivityService.recordFailure(
                    mfaToken.getUser().getEmail(),
                    "OTP expired"
            );
            log.warn("AuthService.verifyOtp(): OTP expired id={}", request.getId());
            throw new InvalidTokenException("Token is expired");
        }

        // 3. OTP mismatch
        String submittedOtp = request.getOtp().trim();
        if (!mfaToken.getOtp().equals(submittedOtp)) {
            //Record activity for wrong password
            loginActivityService.recordFailure(mfaToken.getUser().getEmail(), "Wrong OTP entered");
            log.warn("AuthService.verifyOtp(): wrong OTP entered for id={}", request.getId());
            throw new InvalidCredentialsException("Wrong OTP. Please enter correct OTP");
        }

        // 4. Mark token as used
        mfaToken.setUsed(true);
        mfaTokenRepository.save(mfaToken);

        // 5. Fetch user
        User user = mfaToken.getUser();

        // 6. Record login activity (this also triggers IpMonitoring + risk logging)
        loginActivityService.recordSuccess(user.getId(), user.getEmail());
        log.info("AuthService.verifyOtp(): user verified email={}", user.getEmail());

        // 7. ✅ TRUST THIS DEVICE (NEW)
        try {
            DeviceInfo deviceInfo = UserAgentParser.parse(userAgent);
            String deviceSignature = deviceInfo.getSignature();

            trustedDeviceService.trustDevice(
                    user.getId(),
                    deviceSignature,
                    deviceInfo.getDeviceName()
            );

            log.info("AuthService.verifyOtp(): trusted device saved userId={} device={}",
                    user.getId(), deviceInfo.getDeviceName());
        } catch (Exception e) {
            log.warn("AuthService.verifyOtp(): failed to trust device userId={} reason={}",
                    user.getId(), e.getMessage());
        }


        // 1. Invalidate all previous tokens for this user (important)
        refreshTokenRepository.invalidateAllForUser(user.getId());

// 2. Generate new tokens
        String newAccessToken = jwtUtil.generateAccessToken(user);
        String newRefreshToken = jwtUtil.generateRefreshToken(user);

// 3. Save the new refresh token
        RefreshToken newToken = new RefreshToken();
        newToken.setToken(newRefreshToken);
        newToken.setUser(user);
        newToken.setCreatedAt(LocalDateTime.now());
        newToken.setExpiresAt(LocalDateTime.now().plus(jwtRefreshExpirationMillis, ChronoUnit.MILLIS));
        newToken.setUsed(false);
        newToken.setInvalidated(false);

        refreshTokenRepository.save(newToken);

        log.info("AuthService.verifyOtp(): completed for email={}", user.getEmail());

        String message = mfaToken.isRiskBased()
                ? "Risk-based OTP verified successfully"
                : "MFA OTP verified successfully";

        String type = mfaToken.isRiskBased()
                ? "RISK_VERIFIED"
                : "MFA_VERIFIED";

        // Final response
        return new AuthResponse(
                message,
                type,
                newAccessToken,
                newRefreshToken,
                null
        );
    }

    // Helper to avoid StringIndexOutOfBounds if token is short/null
    private String safeTokenPrefix(String token) {
        if (token == null) return "null";
        return token.length() <= 10 ? token : token.substring(0, 10);
    }

}


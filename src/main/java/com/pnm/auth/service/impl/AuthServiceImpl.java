package com.pnm.auth.service.impl;

import com.pnm.auth.dto.request.*;
import com.pnm.auth.dto.response.AuthResponse;
import com.pnm.auth.dto.response.UserDetailsResponse;
import com.pnm.auth.dto.response.UserIpLogResponse;
import com.pnm.auth.entity.MfaToken;
import com.pnm.auth.entity.RefreshToken;
import com.pnm.auth.entity.User;
import com.pnm.auth.entity.VerificationToken;
import com.pnm.auth.enums.AuthProviderType;
import com.pnm.auth.exception.InvalidCredentialsException;
import com.pnm.auth.exception.InvalidTokenException;
import com.pnm.auth.exception.UserAlreadyExistsException;
import com.pnm.auth.exception.UserNotFoundException;
import com.pnm.auth.repository.MfaTokenRepository;
import com.pnm.auth.repository.RefreshTokenRepository;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.repository.VerificationTokenRepository;
import com.pnm.auth.service.*;
import com.pnm.auth.security.JwtUtil;
import com.pnm.auth.util.BlacklistedTokenStore;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.Caching;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;

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

//    TODO: private final AuditService auditService;                // for future auditing
//     TODO: private final IpDeviceIntelligenceService ipService;   // for future IP/device intelligence

    @Override
    @Transactional
    @CacheEvict(value = {"users.list"}, allEntries = true)
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
            throw new InvalidCredentialsException("Your account has been blocked. Contact support.");
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
            throw new InvalidCredentialsException("Login blocked due to high risk activity.");
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

            return new AuthResponse(
                    "RISK_OTP_REQUIRED",
                    "Suspicious login detected. OTP verification required.",
                    null,
                    null,
                    mfaToken.getId()
            );

            //for verifying opt we will use same controller for which we have used for verifying mfa otp i.e verifyMfaOtp()
        }

        //else low risk - generate tokens

        // Non-MFA user: generate tokens and record successful login
        String newAccessToken = jwtUtil.generateAccessToken(user);
        String newRefreshToken = jwtUtil.generateRefreshToken(user);

        //Delete all tokens related to user
        refreshTokenRepository.deleteAllByUserId(user.getId());

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(newRefreshToken);
        refreshToken.setUser(user);
        refreshToken.setCreatedAt(LocalDateTime.now());
        refreshTokenRepository.save(refreshToken);

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


    @Override
    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest refreshTokenRequest) {

        String oldToken = refreshTokenRequest.getRefreshToken();
        log.info("AuthService.refreshToken(): started (tokenPrefix={})", safeTokenPrefix(oldToken));

        // Check DB record
        RefreshToken tokenEntity = refreshTokenRepository.findByToken(oldToken)
                .orElseThrow(() -> {
                    log.warn("AuthService.refreshToken(): invalid tokenPrefix={}", safeTokenPrefix(oldToken));
                    return new InvalidTokenException("Invalid refresh token");
                });

        // Check expiration
        if (jwtUtil.isTokenExpired(oldToken)) {
            refreshTokenRepository.delete(tokenEntity);
            log.warn("AuthService.refreshToken(): expired token deleted tokenPrefix={}", safeTokenPrefix(oldToken));
            throw new InvalidTokenException("Refresh token is expired");
        }

        // Extract email
        String email = jwtUtil.extractUsername(oldToken);
        log.info("AuthService.refreshToken(): extracted email={}", email);

        // Fetch user
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("AuthService.refreshToken(): user not found email={}", email);
                    return new UserNotFoundException("User not found with email: " + email);
                });

        if (!user.isActive()) {
            log.warn("AuthService.refreshToken(): Blocked user trying to login for email={}", email);
            throw new InvalidTokenException("Your account has been blocked. Contact support.");
        }

        // Rotate tokens (refresh token rotation)
        String newAccessToken = jwtUtil.generateAccessToken(user);
        String newRefreshToken = jwtUtil.generateRefreshToken(user);

        // Delete old refresh token (important!!)
        refreshTokenRepository.delete(tokenEntity);

        // Save new refresh token
        RefreshToken newTokenEntity = new RefreshToken();
        newTokenEntity.setToken(newRefreshToken);
        newTokenEntity.setUser(user);
        newTokenEntity.setCreatedAt(LocalDateTime.now());

        refreshTokenRepository.save(newTokenEntity);

        // Return tokens
        log.info("AuthService.refreshToken(): rotated token successfully for email={}", email);
        return new AuthResponse(
                "TOKEN_REFRESHED",
                "Token refreshed successfully",
                newAccessToken,
                newRefreshToken,
                null);
    }


    @Override
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

        // TODO: loginActivityService.recordLogoutSuccess(...);
        // TODO: auditService.recordLogout(...);

        log.info("AuthService.logout(): finished");
    }


    @Override
    @Transactional
    @Caching(evict = {
            @CacheEvict(value = "users", key = "@jwtUtil.extractUsername(#request.accessToken)"),
            @CacheEvict(value = "users.list", allEntries = true)
    })
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

        // Create new tokens
        String newAccessToken = jwtUtil.generateAccessToken(user);
        String newRefreshToken = jwtUtil.generateRefreshToken(user);
        log.info("AuthService.changePassword(): created new accessToken and refreshToken for email={}",email);

        // Save refresh token to DB
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(newRefreshToken);
        refreshToken.setUser(user);
        refreshToken.setCreatedAt(LocalDateTime.now());
        refreshTokenRepository.save(refreshToken);

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

        //Record LoginActivity after successful otp verification
        loginActivityService.recordSuccess(user.getId(), user.getEmail());
        log.info("AuthService.verifyOtp(): user verified email={}", user.getEmail());

        // 6. Create new tokens
        String accessToken = jwtUtil.generateAccessToken(user);
        String refreshTokenStr = jwtUtil.generateRefreshToken(user);

        // Remove old refresh tokens
        refreshTokenRepository.deleteAllByUserId(user.getId());

        // Save new refresh token
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(refreshTokenStr);
        refreshToken.setUser(user);
        refreshToken.setCreatedAt(LocalDateTime.now());
        refreshTokenRepository.save(refreshToken);

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
                accessToken,
                refreshTokenStr,
                null
        );
    }

    // Helper to avoid StringIndexOutOfBounds if token is short/null
    private String safeTokenPrefix(String token) {
        if (token == null) return "null";
        return token.length() <= 10 ? token : token.substring(0, 10);
    }

}


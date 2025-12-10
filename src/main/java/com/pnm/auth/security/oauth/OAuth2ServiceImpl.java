package com.pnm.auth.security.oauth;

import com.pnm.auth.dto.response.AuthResponse;
import com.pnm.auth.dto.response.UserIpLogResponse;
import com.pnm.auth.entity.MfaToken;
import com.pnm.auth.entity.RefreshToken;
import com.pnm.auth.entity.User;
import com.pnm.auth.enums.AuditAction;
import com.pnm.auth.enums.AuthProviderType;
import com.pnm.auth.exception.*;
import com.pnm.auth.repository.MfaTokenRepository;
import com.pnm.auth.repository.RefreshTokenRepository;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.security.JwtUtil;
import com.pnm.auth.service.EmailService;
import com.pnm.auth.service.IpMonitoringService;
import com.pnm.auth.service.LoginActivityService;
import com.pnm.auth.service.SuspiciousLoginAlertService;
import com.pnm.auth.util.Audit;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.user.OAuth2User;
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
public class OAuth2ServiceImpl implements OAuth2Service {

    private final OAuth2Util oAuth2Util;
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;
    private final LoginActivityService loginActivityService;
    private final IpMonitoringService ipMonitoringService;
    private final MfaTokenRepository mfaTokenRepository;
    private final EmailService emailService;
    private final SuspiciousLoginAlertService suspiciousLoginAlertService;

    @Value("${jwt.refresh.expiration}")
    private Long jwtRefreshExpirationMillis;


    @Override
    @Transactional
    @Audit(action = AuditAction.OAUTH_LOGIN, description = "OAuth2 login attempt")
    public AuthResponse handleOAuth2LoginRequest(OAuth2User oAuth2User, String registrationId, HttpServletRequest request) {

        log.info("OAuth2Service.handleOAuth2LoginRequest(): started provider={} ", registrationId);
        AuthProviderType authProviderType = oAuth2Util.getProviderTypeFromRegistrationId(registrationId);
        String providerId = oAuth2Util.determineProviderIdFromOAuth2User(oAuth2User, registrationId);
        String email = oAuth2User.getAttribute("email");
        log.info("OAuth2Service.handleOAuth2LoginRequest(): login attempt email={} providerId={} providerType={}",
                email, providerId, authProviderType);


        // Extract IP + device early for both success/failure logs
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null) ip = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");

        User user = userRepository.findByProviderIdAndAuthProviderType(providerId, authProviderType).orElse(null);
        User emailUser = (email != null) ? userRepository.findByEmail(email).orElse(null) : null;

        if (user == null && emailUser == null) {
            // Create new user
            log.info("OAuth2Service.handleOAuth2LoginRequest(): creating new user for email={} provider={}", email, authProviderType);
            String username = oAuth2Util.determineUsernameFromOAuth2User(oAuth2User, registrationId);
            user = new User();
            user.setFullName(username);
            user.setPassword(UUID.randomUUID().toString());
            user.setEmail(email);
            user.setProviderId(providerId);
            user.setAuthProviderType(authProviderType);
            user.setEmailVerified(true);
            user.setRoles(List.of("USER"));
            userRepository.save(user);
        } else if (user == null && emailUser != null) {
            // Email exists
            log.warn("OAuth2Service.handleOAuth2LoginRequest(): account exists for email={} (needs merging)", email);
            loginActivityService.recordFailure(email,"OAuth2 login failed: account exists but not linked");
            throw new UserAlreadyExistsException("The email: "+email+" is already registered. Do you want to merge both accounts?");
        } else {
            // Existing OAuth2 user (user != null)
            log.info("OAuth2Service.handleOAuth2LoginRequest(): existing OAuth user login for email={}", email);

            if (email != null && (user.getEmail() == null || !user.getEmail().equals(email))) {
                user.setEmail(email);
                userRepository.save(user);
            }
        }

        if (user != null && !user.isActive()) {
            log.warn("OAuth2Service.handleOAuth2LoginRequest(): Blocked user trying to login for email={}", email);
            loginActivityService.recordFailure(email,"OAuth2 login failed: blocked user");
            throw new AccountBlockedException("Your account has been blocked. Contact support.");
        }

        //SUCCESS: Record login activity
//        loginActivityService.recordSuccess(user.getId(), user.getEmail());

        // -------------------------
        // 4) RISK ENGINE (ONLY FOR NON-MFA USERS)
        // -------------------------
        UserIpLogResponse ipRisk = ipMonitoringService.recordLogin(user.getId(), ip, userAgent);

        int risk = ipRisk.getRiskScore();
        List<String> reasons = ipRisk.getRiskReason() != null
                ? Arrays.asList(ipRisk.getRiskReason().split(","))
                : List.of();

        log.info("OAuth2Service.handleOAuth2LoginRequest(): riskScore={} reasons={}", risk, reasons);

        // -------------------------
        // HIGH RISK → BLOCK LOGIN
        // -------------------------
        if (risk >= 80) {
            log.error("HIGH RISK BLOCKED for email={} riskScore={}", email, risk);
            suspiciousLoginAlertService.sendHighRiskAlert(user, ip, userAgent, reasons);
            loginActivityService.recordFailure(email, "High risk login blocked");
            throw new HighRiskLoginException("Login blocked due to high risk activity.");
        }

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

//             ⭐ THROW EXCEPTION — not return AuthResponse
            throw new RiskOtpRequiredException(
                    "Suspicious login detected. OTP verification required.",
                    mfaToken.getId()
            );
            //for verifying opt we will use same controller for which we have used for verifying mfa otp i.e verifyMfaOtp()
        }

//        refreshTokenRepository.deleteAllByUserId(user.getId());
//
//        //else low risk - generate tokens
//
//        String accessToken = jwtUtil.generateAccessToken(user);
//        String refreshToken = jwtUtil.generateRefreshToken(user);
//
//        refreshTokenRepository.save(new RefreshToken(refreshToken, user, LocalDateTime.now()));

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

        // NOW record success
        loginActivityService.recordSuccess(user.getId(), user.getEmail());

        log.info("OAuth2Service.handleOAuth2LoginRequest(): successful for email={}", user.getEmail());

        return new AuthResponse(
                "AUTH_LOGIN_SUCCESS",
                "Login successful using OAuth2",
                newAccessToken,
                newRefreshToken,
                null);
    }
}

package com.pnm.auth.security.oauth;

import com.pnm.auth.dto.DeviceInfo;
import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.dto.result.MfaResult;
import com.pnm.auth.dto.result.RiskResult;
import com.pnm.auth.entity.User;
import com.pnm.auth.enums.AuditAction;
import com.pnm.auth.enums.AuthOutcome;
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
import com.pnm.auth.service.auth.DeviceTrustService;
import com.pnm.auth.service.auth.MfaService;
import com.pnm.auth.service.auth.RiskEngineService;
import com.pnm.auth.service.auth.TokenService;
import com.pnm.auth.util.Audit;
import com.pnm.auth.util.UserAgentParser;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class OAuth2ServiceImpl implements OAuth2Service{
    private final OAuth2Util oAuth2Util;
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;
    private final LoginActivityService loginActivityService;
    private final IpMonitoringService ipMonitoringService;
    private final MfaTokenRepository mfaTokenRepository;
    private final EmailService emailService;
    private final SuspiciousLoginAlertService suspiciousLoginAlertService;
    private final RiskEngineService riskEngineService;
    private final MfaService mfaService;
    private final TokenService tokenService;
    private final DeviceTrustService deviceTrustService;

    @Value("${jwt.refresh.expiration}")
    private Long jwtRefreshExpirationMillis;


//    @Override
//    @Transactional
//    @Caching(evict = {
//            @CacheEvict(value = "users", key = "#request.getHeader('Authorization')"),
//            @CacheEvict(value = "users.list", allEntries = true)
//    })
//    @Audit(action = AuditAction.OAUTH_LOGIN, description = "OAuth2 login attempt")
//    public AuthResponse handleOAuth2LoginRequest(OAuth2User oAuth2User, String registrationId, HttpServletRequest request) {
//
//        log.info("OAuth2Service.handleOAuth2LoginRequest(): started provider={} ", registrationId);
//        AuthProviderType authProviderType = oAuth2Util.getProviderTypeFromRegistrationId(registrationId);
//        String providerId = oAuth2Util.determineProviderIdFromOAuth2User(oAuth2User, registrationId);
//        String email = oAuth2User.getAttribute("email");
//        log.info("OAuth2Service.handleOAuth2LoginRequest(): login attempt email={} providerId={} providerType={}",
//                email, providerId, authProviderType);
//
//
//        // Extract IP + device early for both success/failure logs
//        String ip = request.getHeader("X-Forwarded-For");
//        if (ip == null) ip = request.getRemoteAddr();
//        String userAgent = request.getHeader("User-Agent");
//
//        // 1) Handle missing email
//        if (email == null) {
//            log.warn("OAuth2 login failed: provider did not supply email");
//            throw new OAuth2LoginFailedException("Provider did not supply email");
//        }
//
//        User user = userRepository.findByProviderIdAndAuthProviderType(providerId, authProviderType).orElse(null);
//        User emailUser = (email != null) ? userRepository.findByEmail(email).orElse(null) : null;
//
//        // 2) New OAuth user
//        if (user == null && emailUser == null) {
//            log.info("OAuth2Service.handleOAuth2LoginRequest(): creating new user for email={} provider={}", email, authProviderType);
//
//            String username = oAuth2Util.determineUsernameFromOAuth2User(oAuth2User, registrationId);
//
//            user = new User();
//            user.setFullName(username);
//            user.setPassword(UUID.randomUUID().toString());
//            user.setEmail(email);
//            user.setProviderId(providerId);
//            user.setAuthProviderType(authProviderType);
//            user.setEmailVerified(true);
//            user.setRoles(List.of("USER"));
//
//            userRepository.save(user);
//
//            // 3) Email exists but not linked(merge or not)
//        } else if (user == null && emailUser != null) {
//            log.warn("OAuth2Service.handleOAuth2LoginRequest(): account exists for email={} (needs merging)", email);
//            loginActivityService.recordFailure(email,"OAuth2 login failed: account exists but not linked");
//            throw new UserAlreadyExistsException("The email: "+email+" is already registered. Do you want to merge both accounts?");
//        }
//        // 4) Existing OAuth user
//        else {
//            log.info("OAuth2Service.handleOAuth2LoginRequest(): existing OAuth user login for email={}", email);
//
//            if (email != null && (user.getEmail() == null || !user.getEmail().equals(email))) {
//                user.setEmail(email);
//                userRepository.save(user);
//            }
//        }
//
//        if (user != null && !user.isActive()) {
//            log.warn("OAuth2Service.handleOAuth2LoginRequest(): Blocked user trying to login for email={}", email);
//            loginActivityService.recordFailure(email,"OAuth2 login failed: blocked user");
//            throw new AccountBlockedException("Your account has been blocked. Contact support.");
//        }
//
//
//        // 4) RISK ENGINE (ONLY FOR NON-MFA USERS)
//
//        UserIpLogResponse ipRisk = ipMonitoringService.recordLogin(user.getId(), ip, userAgent);
//
//        int risk = ipRisk.getRiskScore();
//        List<String> reasons = ipRisk.getRiskReason() != null
//                ? Arrays.asList(ipRisk.getRiskReason().split(","))
//                : List.of();
//
//        log.info("OAuth2Service.handleOAuth2LoginRequest(): riskScore={} reasons={}", risk, reasons);
//
//        // HIGH RISK → BLOCK LOGIN
//        if (risk >= 80) {
//            log.error("HIGH RISK BLOCKED for email={} riskScore={}", email, risk);
//            suspiciousLoginAlertService.sendHighRiskAlert(user, ip, userAgent, reasons);
//            loginActivityService.recordFailure(email, "High risk login blocked");
//            throw new HighRiskLoginException("Login blocked due to high risk activity.");
//        }
//
//        if (risk >= 40) {
//            log.warn("MEDIUM RISK login, OTP required email={} risk={}", email, risk);
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
//                mfaTokenRepository.save(mfaToken);
//
//                emailService.sendMfaOtpEmail(user.getEmail(), otp);
//
    ////              THROW EXCEPTION — not return AuthResponse
//                throw new RiskOtpRequiredException(
//                        "Suspicious login detected. OTP verification required.",
//                        mfaToken.getId()
//                );
//            }catch (Exception ex) {
//                log.error("OAuth2Service.handleOAuth2LoginRequest(): Medium-risk OTP flow failed email={} msg={}", email, ex.getMessage(), ex);
//                loginActivityService.recordFailure(email, "Failed to send medium-risk OTP");
//                throw new EmailSendFailedException("Failed to send OTP. Please try again later.");
//            }
//            //for verifying opt we will use same controller for which we have used for verifying mfa otp i.e verifyMfaOtp()
//        }
//
//        try {
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
//            // NOW record success
//            try {
//                loginActivityService.recordSuccess(user.getId(), user.getEmail());
//            } catch (Exception ex) {
//                log.error("OAuth2Service.handleOAuth2LoginRequest(): failed to record login success for userId={}, message={}",
//                        user.getId(), ex.getMessage(), ex);
//            }
//            log.info("OAuth2Service.handleOAuth2LoginRequest(): successful for email={}", user.getEmail());
//
//            return new AuthResponse(
//                    "AUTH_LOGIN_SUCCESS",
//                    "Login successful using OAuth2",
//                    newAccessToken,
//                    newRefreshToken,
//                    null);
//        }
//        catch (Exception ex){
//            log.error("OAuth2Service.handleOAuth2LoginRequest(): access and refresh tokens generation failed for email={}, message={}",
//                    email, ex.getMessage(), ex);
//            loginActivityService.recordFailure(email, "Failed to generate access and refresh tokens");
//            throw new TokenGenerationException("Login failed. Please try again later.");
//        }
//    }


    @Override
    @Transactional
    @Audit(action = AuditAction.OAUTH_LOGIN, description = "OAuth2 login attempt")
    public AuthenticationResult handleOAuth2LoginRequest(
            OAuth2User oAuth2User,
            String registrationId,
            HttpServletRequest request
    ) {

        log.info("OAuth2Service.handleOAuth2LoginRequest(): started provider={} ", registrationId);

        AuthProviderType providerType = oAuth2Util.getProviderTypeFromRegistrationId(registrationId);

        String providerId = oAuth2Util.determineProviderIdFromOAuth2User(oAuth2User, registrationId);

        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null) ip = request.getRemoteAddr();

        String userAgent = request.getHeader("User-Agent");

        // 1️⃣ Resolve OAuth user
        User user = resolveOrCreateUser(oAuth2User, providerType, providerId);

        // 2️⃣ Blocked user?
        if (!user.isActive()) {
            log.warn("OAuth2Service.handleOAuth2LoginRequest(): Blocked user trying to login for email={}", user.getEmail());
            loginActivityService.recordFailure(user.getEmail(),"OAuth2 login failed: blocked user");
            throw new AccountBlockedException("Your account has been blocked. Contact support.");
        }

        // 3️⃣ Risk evaluation (shared)
        RiskResult risk = riskEngineService.evaluateRisk(user, ip, userAgent);

        if (risk.getScore() >= 80) {
            log.error("HIGH RISK BLOCKED for email={} riskScore={}",user.getEmail(), risk.getScore());
            suspiciousLoginAlertService.sendHighRiskAlert(user, ip, userAgent, risk.getReasons());
            loginActivityService.recordFailure(user.getEmail(), "High risk login blocked");
            throw new HighRiskLoginException("Login blocked due to high risk activity.");
        }

        if (risk.getScore() >= 40) {
            return handleMediumRiskOtp(user);
        }

        // 4️⃣ Low risk → success
        AuthenticationResult result = tokenService.generateTokens(user);

        // 5️⃣ Persist IP/device login (BEST-EFFORT, NON-BLOCKING)
        try {
            ipMonitoringService.recordLogin(user.getId(), ip, userAgent);
        } catch (Exception ex) {
            log.warn("OAuth login: ipMonitoring failed userId={} msg={}",
                    user.getId(), ex.getMessage());
        }

        try {
            DeviceInfo deviceInfo = UserAgentParser.parse(userAgent);
            deviceTrustService.trustDevice(
                    user.getId(),
                    deviceInfo.getSignature(),
                    deviceInfo.getDeviceName()
            );
        } catch (Exception ex) {
            log.warn("OAuth login: failed to trust device userId={} msg={}",
                    user.getId(), ex.getMessage());
        }

        return AuthenticationResult.builder()
                .outcome(result.getOutcome())
                .accessToken(result.getAccessToken())
                .refreshToken(result.getRefreshToken())
                .message("Login successful")
                .user(user)
                .build();
    }


    private User resolveOrCreateUser(
            OAuth2User oAuth2User,
            AuthProviderType providerType,
            String providerId
    ) {

        String email = oAuth2User.getAttribute("email");

        if (email == null) {
            log.warn("OAuth2 login failed: provider did not supply email");
            throw new OAuth2LoginFailedException("Provider did not supply email");
        }

        User user = userRepository.findByProviderIdAndAuthProviderType(providerId, providerType).orElse(null);

        User emailUser = userRepository.findByEmail(email).orElse(null);

        // New user
        if (user == null && emailUser == null) {
            log.info("OAuth2Service.handleOAuth2LoginRequest(): creating new user for email={} provider={}", email, providerType.name());
            String username = oAuth2Util.determineUsernameFromOAuth2User(oAuth2User, providerType.name());

            user = new User();
            user.setFullName(username);
            user.setEmail(email);
            user.setPassword(UUID.randomUUID().toString());
            user.setProviderId(providerId);
            user.setAuthProviderType(providerType);
            user.setEmailVerified(true);
            user.setRoles(List.of("USER"));

            return userRepository.save(user);
        }

        // Email exists but not linked
        if (user == null) {
            log.warn("OAuth2Service.handleOAuth2LoginRequest(): account exists for email={} (needs merging)", email);
            loginActivityService.recordFailure(email,"OAuth2 login failed: account exists but not linked");
            throw new UserAlreadyExistsException("The email: "+email+" is already registered. Do you want to merge both accounts?");
        }

        // Sync email if changed
        if (!email.equals(user.getEmail())) {
            user.setEmail(email);
            userRepository.save(user);
        }

        return user;
    }



    private AuthenticationResult handleMediumRiskOtp(User user) {
        try {
            MfaResult mfa = mfaService.handleMediumRiskOtp(user);

            if (mfa.getOutcome() == AuthOutcome.RISK_OTP_REQUIRED) {
                throw new RiskOtpRequiredException(
                        "Suspicious login detected. OTP required.",
                        mfa.getTokenId()
                );
            }

            throw new IllegalStateException("Unexpected Risk OTP outcome");

        } catch (EmailSendFailedException ex) {
            throw ex;

        } catch (Exception ex) {
            log.error("OAuth2Service: medium-risk OTP error email={} err={}",
                    user.getEmail(), ex.getMessage(), ex);
            throw new EmailSendFailedException("Failed to send OTP. Try again later.");
        }
    }
}

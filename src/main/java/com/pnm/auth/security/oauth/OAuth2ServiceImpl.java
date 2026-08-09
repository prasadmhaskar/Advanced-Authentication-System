package com.pnm.auth.security.oauth;

import com.pnm.auth.domain.enums.NextAction;
import com.pnm.auth.dto.response.UserResponse;
import com.pnm.auth.dto.result.*;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.domain.enums.AuthProviderType;
import com.pnm.auth.event.SuccessEvent;
import com.pnm.auth.exception.custom.*;
import com.pnm.auth.service.interfaces.email.EmailService;
import com.pnm.auth.service.interfaces.ipmonitoring.IpMonitoringService;
import com.pnm.auth.service.interfaces.login.ActivityService;
import com.pnm.auth.service.interfaces.device.DeviceTrustService;
import com.pnm.auth.service.interfaces.auth.MfaService;
import com.pnm.auth.service.interfaces.risk.RiskEngineService;
import com.pnm.auth.service.interfaces.auth.TokenService;
import com.pnm.auth.util.MaskingUtil;
import com.pnm.auth.util.OAuth2Util;
import com.pnm.auth.util.UserAgentParser;
import com.pnm.auth.web.context.RequestContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


@Service
    @RequiredArgsConstructor
    @Slf4j
    @Transactional
    public class OAuth2ServiceImpl implements OAuth2Service {

        private final OAuth2Util oAuth2Util;
        private final OAuthPersistenceService oAuthPersistenceService;
        private final ActivityService activityService;
        private final IpMonitoringService ipMonitoringService;
        private final RiskEngineService riskEngineService;
        private final MfaService mfaService;
        private final TokenService tokenService;
        private final DeviceTrustService deviceTrustService;
        private final EmailService emailService;
        private final ApplicationEventPublisher eventPublisher;

        @Value("${auth.risk.threshold.high}")
        private int highRiskScore;

        @Value("${auth.risk.threshold.medium}")
        private int mediumRiskScore;

        @Override
        public AuthenticationResult handleOAuth2LoginRequest(
                OAuth2User oAuth2User,
                String registrationId,
                RequestContext ctx
        ) {
            log.info("OAuth2Service: started provider={}", registrationId);


            String ip = ctx.ip();
            String userAgent = ctx.userAgent();

            AuthProviderType providerType = oAuth2Util.getProviderTypeFromRegistrationId(registrationId);
            String providerId = oAuth2Util.determineProviderIdFromOAuth2User(oAuth2User, registrationId);

            // Resolve user or create new
            ResolveOAuthResult resolveResult = oAuthPersistenceService.resolveOrCreateUser(
                    oAuth2User, providerType, providerId, ip, userAgent
            );

            // Handle Link Required
            if (resolveResult.getOutcome() == AuthOutcome.LINK_REQUIRED) {
                return AuthenticationResult.builder()
                        .outcome(AuthOutcome.LINK_REQUIRED)
                        .email(resolveResult.getEmail())
                        .existingProvider(resolveResult.getExistingProvider())
                        .attemptedProvider(providerType)
                        .nextAction(NextAction.LINK_OAUTH)
                        .linkToken(resolveResult.getLinkToken())
                        .message("Account linking required")
                        .build();
            }

            User user = resolveResult.getUser();

            // Check Blocked Status
            if (!user.isActive()) {
                activityService.recordFailure(user.getId(), user.getEmail(), ip, userAgent, "Blocked user trying OAuth login");
                throw new AccountBlockedException("Your account has been blocked.");
            }

            // Record success only if it's a new registration
            if (resolveResult.isNewUser()) {
                try {
                    ipMonitoringService.recordRegistrationIpDetails(user.getId(), ip, userAgent);
                } catch (Exception ex) {
                    log.warn("OAuth2Service: Failed to audit OAuth registration userId={}", user.getId());
                }
            }

            if (!resolveResult.isNewUser()) {
                // Risk Engine
                RiskResult risk = riskEngineService.evaluateRisk(user.getId(), ip, userAgent);

                if (risk.getScore() >= highRiskScore) {
                    log.warn("OAuth2Service: HIGH RISK → login blocked for ip={} and security email sent to email={}", ip, MaskingUtil.maskEmail(user.getEmail()));
                    emailService.sendHighRiskAlert(user.getEmail(), ip, userAgent, risk.getReasons());
                    activityService.recordFailure(user.getId(), user.getEmail(), ip, userAgent, "High risk OAuth login");
                    throw new HighRiskLoginException("Login blocked due to high risk activity.");
                }

                if (risk.getScore() >= mediumRiskScore) {
                    log.warn("OAuth2Service: MEDIUM RISK → OTP required for ip={} and email={}", ip, MaskingUtil.maskEmail(user.getEmail()));
                    MfaResult mfaResult = mfaService.handleMediumRiskOtp(user);

                    return AuthenticationResult.builder()
                            .outcome(mfaResult.getOutcome())
                            .otpTokenId(mfaResult.getTokenId())
                            .message("Suspicious login detected, verification needed. OTP has been sent to your email.")
                            .build();
                }

                eventPublisher.publishEvent(new SuccessEvent(user.getId(), user.getEmail(), ip, userAgent, "OAuth login successful"));
            }

            // Generate tokens
            AuthenticationResult tokenResult = tokenService.generateTokens(user, ctx);

            //
            try {
                var device = UserAgentParser.parse(userAgent);
                deviceTrustService.trustDevice(user.getId(), device.getSignature(), device.getDeviceName());
            } catch (Exception ex) {
                log.warn("OAuth login post-processing failed userId={}", user.getId());
            }

            return AuthenticationResult.builder()
                    .outcome(AuthOutcome.SUCCESS)
                    .accessToken(tokenResult.getAccessToken())
                    .refreshToken(tokenResult.getRefreshToken())
                    .user(UserResponse.from(user))
                    .message("Login successful")
                    .build();
        }

    }

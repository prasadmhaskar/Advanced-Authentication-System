package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.domain.enums.NextAction;
import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.dto.result.EmailVerificationResult;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.entity.VerificationToken;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.event.LoginSuccessEvent;
import com.pnm.auth.exception.custom.InvalidTokenException;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.repository.VerificationTokenRepository;
import com.pnm.auth.service.auth.TokenService;
import com.pnm.auth.service.device.DeviceTrustService;
import com.pnm.auth.service.ipmonitoring.IpMonitoringService;
import com.pnm.auth.service.login.LoginActivityService;
import com.pnm.auth.util.UserAgentParser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class VerifyEmailOrchestratorImpl implements VerifyEmailOrchestrator {

    private final VerificationTokenRepository verificationTokenRepository;
    private final UserRepository userRepository;
    private final TokenService tokenService;
    private final ApplicationEventPublisher eventPublisher;
    private final DeviceTrustService deviceTrustService;
    private final IpMonitoringService ipMonitoringService;

    @Override
    @Transactional
    public EmailVerificationResult verify(String rawToken, String ip, String ua) {

        String token = rawToken.trim();

        log.info("VerifyEmailOrchestrator: started tokenPrefix={}", token.length() > 8 ? token.substring(0,8) : "short");

        // 1️⃣ Load token
        VerificationToken verificationToken =
                verificationTokenRepository.findByTokenAndUsedAtIsNull(token)
                        .orElseThrow(() -> {
                            log.warn("VerifyEmailOrchestrator: invalid or already used token");
                            return new InvalidTokenException("Invalid or expired token");
                        });

        // 2️⃣ Validate type
        if (!"EMAIL_VERIFICATION".equals(verificationToken.getType())) {
            log.warn("VerifyEmailOrchestrator: token type mismatch expected=EMAIL_VERIFICATION actual={}",
                    verificationToken.getType());
            throw new InvalidTokenException("Invalid verification token");
        }

        // 3️⃣ Validate expiry
        if (verificationToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            log.warn("VerifyEmailOrchestrator: token expired");
            throw new InvalidTokenException("Verification link expired");
        }

        // 4️⃣ Verify user
        User user = verificationToken.getUser();

        if (user.getEmailVerified()) {
            log.info("VerifyEmailOrchestrator: email already verified email={}", user.getEmail());
            return EmailVerificationResult.builder()
                    .outcome(AuthOutcome.SUCCESS)
                    .email(user.getEmail())
                    .nextAction(NextAction.LOGIN)
                    .build();
        }
        user.setEmailVerified(true);
        verificationToken.setUsedAt(LocalDateTime.now());

        userRepository.save(user);
        verificationTokenRepository.save(verificationToken);

        AuthenticationResult result = tokenService.generateTokens(user);


        log.info("VerifyEmailOrchestrator: email verified email={}", user.getEmail());

        eventPublisher.publishEvent(
                new LoginSuccessEvent(
                        user.getId(),
                        user.getEmail(),
                        ip,
                        ua));

        //Record login
        ipMonitoringService.recordFirstLogin(user.getId(), ip, ua);

        //Add to trustedDevice
        try {
            var agent = UserAgentParser.parse(ua);
            deviceTrustService.trustDevice(
                    user.getId(),
                    agent.getSignature(),
                    agent.getDeviceName()
            );
        } catch (Exception ex) {
            log.warn("VerifyEmailOrchestrator: failed to trust device email={} err={}",
                    user.getEmail(), ex.getMessage());
        }

        return EmailVerificationResult.builder()
                .outcome(AuthOutcome.SUCCESS)
                .email(user.getEmail())
                .accessToken(result.getAccessToken())
                .refreshToken(result.getRefreshToken())
                .nextAction(NextAction.LOGIN)
                .build();
    }
}


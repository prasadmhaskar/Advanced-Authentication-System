package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.domain.enums.NextAction;
import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.dto.result.EmailVerificationResult;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.entity.VerificationToken;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.event.LoginSuccessEvent;
import com.pnm.auth.exception.custom.AccountBlockedException;
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

    @Override
    @Transactional
    public EmailVerificationResult verify(String rawToken, String ip, String ua) {

        String token = rawToken.trim();

        log.info("VerifyEmailOrchestrator: started for tokenPrefix={}", token.length() > 8 ? token.substring(0,8) : "short");

        // 1️⃣ Load token
        VerificationToken verificationToken =
                verificationTokenRepository.findByTokenAndUsedAtIsNull(token)
                        .orElseThrow(() -> {
                            log.warn("VerifyEmailOrchestrator: invalid or already used token");
                            return new InvalidTokenException("Invalid or expired verification link, please resend verification link and try again");
                        });

        // 2️⃣ Validate type
        if (!"EMAIL_VERIFICATION".equals(verificationToken.getType())) {
            log.warn("VerifyEmailOrchestrator: token type mismatch expected=EMAIL_VERIFICATION actual={}",
                    verificationToken.getType());
            throw new InvalidTokenException("Invalid verification link, please resend verification link and try again");
        }

        // 3️⃣ Validate expiry
        if (verificationToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            log.warn("VerifyEmailOrchestrator: token expired");
            throw new InvalidTokenException("Verification link expired, please resend verification link and try again");
        }

        // 4️⃣ Verify user
        User user = verificationToken.getUser();

        if (!user.isActive()) {
            throw new AccountBlockedException("Account is blocked.");
        }

        if (user.getEmailVerified()) {
            log.info("VerifyEmailOrchestrator: email already verified email={}", user.getEmail());
            return EmailVerificationResult.builder()
                    .outcome(AuthOutcome.SUCCESS)
                    .email(user.getEmail())
                    .nextAction(NextAction.LOGIN)
                    .build();
        }


        // 4️⃣ ATOMIC LOCK (The Fix)
        // We only mark the token. We DO NOT update the user here.
        int rowsUpdated = verificationTokenRepository.markAsUsed(verificationToken.getId());

        if (rowsUpdated == 0) {
            // RACE CONDITION HIT: Another thread used this token 1ms ago.
            // We return SUCCESS (Idempotent) but do NOT issue new tokens.
            log.info("VerifyEmailOrchestrator: Race condition caught. Token already used.");
            return EmailVerificationResult.builder()
                    .outcome(AuthOutcome.SUCCESS)
                    .email(user.getEmail())
                    .nextAction(NextAction.LOGIN)
                    .build();
        }

        // 5️⃣ Update User (Since we won the lock)
        user.setEmailVerified(true);
        userRepository.save(user); // Standard JPA save

        AuthenticationResult result = tokenService.generateTokens(user);

        eventPublisher.publishEvent(
                new LoginSuccessEvent(
                        user.getId(),
                        user.getEmail(),
                        ip,
                        ua));

        //Add to trustedDevice
        try {
            var agent = UserAgentParser.parse(ua);
            deviceTrustService.trustDevice(user.getId(), agent.getSignature(), agent.getDeviceName());
        } catch (Exception ex) {
            log.warn("VerifyEmailOrchestrator: failed to trust device email={} err={}",
                    user.getEmail(), ex.getMessage());
        }

        log.info("VerifyEmailOrchestrator: finished, verified email={}", user.getEmail());

        return EmailVerificationResult.builder()
                .outcome(AuthOutcome.SUCCESS)
                .email(user.getEmail())
                .accessToken(result.getAccessToken())
                .refreshToken(result.getRefreshToken())
                .nextAction(NextAction.LOGIN)
                .build();
    }
}


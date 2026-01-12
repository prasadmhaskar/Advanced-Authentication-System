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
import com.pnm.auth.util.UserAgentParser;
import com.pnm.auth.web.context.RequestContext;
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
    public EmailVerificationResult verify(String rawToken, RequestContext ctx) {

        String token = rawToken.trim();

        log.info("VerifyEmailOrchestrator: started");

        // Load token
        VerificationToken verificationToken =
                verificationTokenRepository.findByTokenAndUsedAtIsNull(token)
                        .orElseThrow(() -> {
                            log.warn("VerifyEmailOrchestrator: invalid or already used token");
                            return new InvalidTokenException("Invalid or expired verification link, please resend verification link and try again");
                        });

        // Validate token type
        if (!"EMAIL_VERIFICATION".equals(verificationToken.getType())) {
            log.warn("VerifyEmailOrchestrator: token type mismatch expected=EMAIL_VERIFICATION actual={}",
                    verificationToken.getType());
            throw new InvalidTokenException("Invalid verification link, please resend verification link and try again");
        }

        // Validate token expiry
        if (verificationToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            log.warn("VerifyEmailOrchestrator: token expired");
            throw new InvalidTokenException("Verification link expired, please resend verification link and try again");
        }

        // Load user
        User user = verificationToken.getUser();

        // Check account is blocked or not
        if (!user.isActive()) {
            log.warn("VerifyEmailOrchestrator: Blocked user tried to verify account");
            throw new AccountBlockedException("Account is blocked.");
        }

        // Check email is verified or not
        if (user.getEmailVerified()) {
            log.info("VerifyEmailOrchestrator: email already verified email={}", user.getEmail());
            return EmailVerificationResult.builder()
                    .outcome(AuthOutcome.SUCCESS)
                    .email(user.getEmail())
                    .nextAction(NextAction.LOGIN)
                    .build();
        }

        // We only mark the token. We do not update the user here.
        int rowsUpdated = verificationTokenRepository.markAsUsed(verificationToken.getId());

        // if a user clicks 2 times on a verification link within milliseconds. To avoid 2 times verification.
        // If there is any signup bonus user will get it two times hence to avoid it, this is necessary.
        if (rowsUpdated == 0) {
            // RACE CONDITION: Another thread used this token millisecond ago.
            log.info("VerifyEmailOrchestrator: Race condition caught. Token already used.");
            return EmailVerificationResult.builder()
                    .outcome(AuthOutcome.SUCCESS)
                    .email(user.getEmail())
                    .nextAction(NextAction.LOGIN)
                    .build();
        }

        // Update User
        user.setEmailVerified(true);
        user.incrementTokenVersion();
        userRepository.save(user);

        AuthenticationResult result = tokenService.generateTokens(user, ctx);

        // Record login success- Asynchronous
        eventPublisher.publishEvent(
                new LoginSuccessEvent(
                        user.getId(),
                        user.getEmail(),
                        ctx.ip(),
                        ctx.userAgent()));

        // Save this device as trustedDevice
        try {
            var agent = UserAgentParser.parse(ctx.userAgent());
            deviceTrustService.trustDevice(user.getId(), agent.getSignature(), agent.getDeviceName());
        } catch (Exception ex) {
            log.warn("VerifyEmailOrchestrator: failed to trust device email={} err={}",
                    user.getEmail(), ex.getMessage());
        }

        log.info("VerifyEmailOrchestrator: finished for email={}", user.getEmail());

        return EmailVerificationResult.builder()
                .outcome(AuthOutcome.SUCCESS)
                .email(user.getEmail())
                .accessToken(result.getAccessToken())
                .refreshToken(result.getRefreshToken())
                .nextAction(NextAction.LOGIN)
                .build();
    }
}


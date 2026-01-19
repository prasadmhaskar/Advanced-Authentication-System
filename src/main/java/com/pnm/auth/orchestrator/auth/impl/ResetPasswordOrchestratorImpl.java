package com.pnm.auth.orchestrator.auth.impl;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.entity.VerificationToken;
import com.pnm.auth.dto.request.ResetPasswordRequest;
import com.pnm.auth.event.FailureEvent;
import com.pnm.auth.event.SuccessEvent;
import com.pnm.auth.exception.custom.AccountBlockedException;
import com.pnm.auth.exception.custom.InvalidTokenException;
import com.pnm.auth.exception.custom.PasswordResetException;
import com.pnm.auth.orchestrator.auth.ResetPasswordOrchestrator;
import com.pnm.auth.repository.RefreshTokenRepository;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.repository.VerificationTokenRepository;
import com.pnm.auth.service.impl.cache.CacheManagementService;
import com.pnm.auth.web.context.RequestContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.LocalDateTime;

@Slf4j
@RequiredArgsConstructor
@Service
public class ResetPasswordOrchestratorImpl implements ResetPasswordOrchestrator {
    private final VerificationTokenRepository verificationTokenRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final CacheManagementService cacheManagementService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final ApplicationEventPublisher eventPublisher;

    @Override
    @Transactional
    public void resetPassword(ResetPasswordRequest request, RequestContext ctx) {

        log.info("ResetPasswordOrchestrator: started");

        // Load verification token
        VerificationToken token = verificationTokenRepository
                .findByToken(request.getToken())
                .orElseThrow(() -> {
                    log.warn("ResetPasswordOrchestrator: invalid token");
                    return new InvalidTokenException("Invalid or expired reset token");
                });

        // Validate token type
        if (!"PASSWORD_RESET".equals(token.getType())) {
            log.warn("ResetPasswordOrchestrator: token type mismatch");
            throw new InvalidTokenException("Invalid reset token");
        }

        // Validate expiry
        if (token.getExpiresAt().isBefore(LocalDateTime.now())) {
            log.warn("ResetPasswordOrchestrator: token expired");
            throw new InvalidTokenException("Reset token has expired");
        }

        // Load user
        User user = token.getUser();

        // Blocked user check
        if (!user.isActive()) {
            log.warn("ResetPasswordOrchestrator: blocked user tried reset email={}", user.getEmail());
            eventPublisher.publishEvent(new FailureEvent(user.getId(), user.getEmail(), ctx.ip(), ctx.userAgent(), "Blocked user trying to reset password"));
            throw new AccountBlockedException("Your account has been blocked.");
        }

        try {
            // Update password
            user.setPassword(passwordEncoder.encode(request.getNewPassword()));
            user.incrementTokenVersion();
            userRepository.save(user);

            // Delete token after use
            verificationTokenRepository.delete(token);

            // Invalidate all refresh tokens of user
            refreshTokenRepository.invalidateAllForUser(user.getId());

            // Delete user details from cache
            cacheManagementService.evictUserFromCache(user.getEmail());

            eventPublisher.publishEvent(new SuccessEvent(user.getId(), user.getEmail(), ctx.ip(), ctx.userAgent(), "Password reset successfully"));

            log.info("ResetPasswordOrchestrator: finished for email={}", user.getEmail());

        } catch (Exception ex) {
            log.error("ResetPasswordOrchestrator: failed userId={} msg={}",
                    user.getId(), ex.getMessage(), ex);

            throw new PasswordResetException(
                    "Unable to reset password right now. Please try again later."
            );
        }
    }
}

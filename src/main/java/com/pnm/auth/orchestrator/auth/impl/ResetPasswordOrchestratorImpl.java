package com.pnm.auth.orchestrator.auth.impl;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.entity.VerificationToken;
import com.pnm.auth.dto.request.ResetPasswordRequest;
import com.pnm.auth.exception.custom.AccountBlockedException;
import com.pnm.auth.exception.custom.InvalidTokenException;
import com.pnm.auth.exception.custom.PasswordResetException;
import com.pnm.auth.orchestrator.auth.ResetPasswordOrchestrator;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.repository.VerificationTokenRepository;
import com.pnm.auth.service.impl.cache.CacheManagementService;
import com.pnm.auth.service.login.LoginActivityService;
import com.pnm.auth.web.context.RequestContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
    private final LoginActivityService loginActivityService;
    private final CacheManagementService cacheManagementService;

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
            throw new AccountBlockedException("Your account has been blocked.");
        }

        try {
            // Update password
            user.setPassword(passwordEncoder.encode(request.getNewPassword()));
            userRepository.save(user);

            // Delete token after use
            verificationTokenRepository.delete(token);

            // Record success
            try {
                loginActivityService.recordSuccess(user.getId(), user.getEmail(), ctx.ip(), ctx.userAgent());
            } catch (Exception ex) {
                log.warn("ResetPasswordOrchestrator: activity log failed userId={} msg={}",
                        user.getId(), ex.getMessage());
            }

            // Delete user details from cache
            cacheManagementService.evictUserFromCache(user.getEmail());

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

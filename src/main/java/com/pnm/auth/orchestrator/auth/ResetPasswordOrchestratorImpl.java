package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.request.ResetPasswordRequest;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.entity.VerificationToken;
import com.pnm.auth.exception.custom.AccountBlockedException;
import com.pnm.auth.exception.custom.InvalidTokenException;
import com.pnm.auth.exception.custom.PasswordResetException;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.repository.VerificationTokenRepository;
import com.pnm.auth.service.login.LoginActivityService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class ResetPasswordOrchestratorImpl implements ResetPasswordOrchestrator {

    private final VerificationTokenRepository verificationTokenRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final LoginActivityService loginActivityService;

    @Override
    @Transactional
    public void reset(ResetPasswordRequest request , String ip, String userAgent) {

        String tokenPrefix = safeTokenPrefix(request.getToken());
        log.info("ResetPasswordOrchestrator.reset(): started tokenPrefix={}", tokenPrefix);

        // 1️⃣ Load verification token
        VerificationToken token = verificationTokenRepository
                .findByToken(request.getToken())
                .orElseThrow(() -> {
                    log.warn("ResetPasswordOrchestrator: invalid token tokenPrefix={}", tokenPrefix);
                    return new InvalidTokenException("Invalid or expired reset token");
                });

        // 2️⃣ Validate token type
        if (!"PASSWORD_RESET".equals(token.getType())) {
            log.warn("ResetPasswordOrchestrator: token type mismatch tokenPrefix={}", tokenPrefix);
            throw new InvalidTokenException("Invalid reset token");
        }

        // 3️⃣ Validate expiry
        if (token.getExpiresAt().isBefore(LocalDateTime.now())) {
            log.warn("ResetPasswordOrchestrator: token expired tokenPrefix={}", tokenPrefix);
            throw new InvalidTokenException("Reset token has expired");
        }

        User user = token.getUser();

        // 4️⃣ Blocked user check
        if (!user.isActive()) {
            log.warn("ResetPasswordOrchestrator: blocked user tried reset email={}", user.getEmail());
            throw new AccountBlockedException("Your account has been blocked.");
        }

        try {
            // 5️⃣ Update password
            user.setPassword(passwordEncoder.encode(request.getNewPassword()));
            userRepository.save(user);

            // 6️⃣ Delete token after use
            verificationTokenRepository.delete(token);

            // 7️⃣ Record audit / activity (best-effort)
            try {
                loginActivityService.recordSuccess(user.getId(), user.getEmail(), ip, userAgent);
            } catch (Exception ex) {
                log.warn("ResetPasswordOrchestrator: activity log failed userId={} msg={}",
                        user.getId(), ex.getMessage());
            }

            log.info("ResetPasswordOrchestrator.reset(): completed userId={}", user.getId());

        } catch (Exception ex) {
            log.error("ResetPasswordOrchestrator.reset(): failed userId={} msg={}",
                    user.getId(), ex.getMessage(), ex);

            throw new PasswordResetException(
                    "Unable to reset password right now. Please try again later."
            );
        }
    }

    private String safeTokenPrefix(String token) {
        if (token == null) return "null";
        return token.length() <= 10 ? token : token.substring(0, 10);
    }
}


package com.pnm.auth.service.impl.auth;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.entity.VerificationToken;
import com.pnm.auth.dto.request.ResetPasswordRequest;
import com.pnm.auth.exception.custom.AccountBlockedException;
import com.pnm.auth.exception.custom.InvalidTokenException;
import com.pnm.auth.exception.custom.PasswordResetException;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.repository.VerificationTokenRepository;
import com.pnm.auth.service.auth.PasswordResetService;
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
public class PasswordResetServiceImpl implements PasswordResetService {

    private final VerificationTokenRepository verificationTokenRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final LoginActivityService loginActivityService;

    @Override
    @Transactional
    public void resetPassword(ResetPasswordRequest request, RequestContext ctx) {
        String ip = ctx.ip();
        String userAgent = ctx.userAgent();

        log.info("PasswordResetService: started ip={}",ip);

        // Load verification token
        VerificationToken token = verificationTokenRepository
                .findByToken(request.getToken())
                .orElseThrow(() -> {
                    log.warn("PasswordResetService: invalid token for ip={}",ip);
                    return new InvalidTokenException("Invalid or expired reset token");
                });

        // Validate token type
        if (!"PASSWORD_RESET".equals(token.getType())) {
            log.warn("PasswordResetService: token type mismatch for ip={}",ip);
            throw new InvalidTokenException("Invalid reset token");
        }

        // Validate expiry
        if (token.getExpiresAt().isBefore(LocalDateTime.now())) {
            log.warn("PasswordResetService: token expired for ip={}",ip);
            throw new InvalidTokenException("Reset token has expired");
        }

        // Load user
        User user = token.getUser();

        // Blocked user check
        if (!user.isActive()) {
            log.warn("PasswordResetService: blocked user tried reset email={}", user.getEmail());
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
                loginActivityService.recordSuccess(user.getId(), user.getEmail(), ip, userAgent);
            } catch (Exception ex) {
                log.warn("PasswordResetService: activity log failed userId={} msg={}",
                        user.getId(), ex.getMessage());
            }

            log.info("PasswordResetService: finished ip={} and email={}",ip, user.getEmail());

        } catch (Exception ex) {
            log.error("PasswordResetService: failed userId={} msg={}",
                    user.getId(), ex.getMessage(), ex);

            throw new PasswordResetException(
                    "Unable to reset password right now. Please try again later."
            );
        }
    }
}

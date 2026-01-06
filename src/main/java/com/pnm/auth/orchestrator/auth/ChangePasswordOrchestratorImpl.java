package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.request.ChangePasswordRequest;
import com.pnm.auth.dto.response.UserResponse;
import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuditAction;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.exception.custom.*;
import com.pnm.auth.repository.RefreshTokenRepository;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.util.AuthUtil;
import com.pnm.auth.util.JwtUtil;
import com.pnm.auth.service.login.LoginActivityService;
import com.pnm.auth.service.auth.TokenService;
import com.pnm.auth.util.Audit;
import com.pnm.auth.web.context.RequestContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Caching;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class ChangePasswordOrchestratorImpl implements ChangePasswordOrchestrator {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenRepository refreshTokenRepository;
    private final TokenService tokenService;
    private final LoginActivityService loginActivityService;
    private final AuthUtil authUtil;

    @Override
    @Transactional
    @Caching(evict = {@CacheEvict(value = "users", key = "#accessToken"),
            @CacheEvict(value = "users.list", allEntries = true)})
    @Audit(action = AuditAction.CHANGE_PASSWORD, description = "User password change")
    public AuthenticationResult changePassword(ChangePasswordRequest request, RequestContext ctx)
    {
        String ip = ctx.ip();
        String userAgent = ctx.userAgent();

        log.info("ChangePasswordOrchestrator: started for ip={}", ip);

        String email = authUtil.getCurrentEmail();

        // --------------------------------------------------
        // 3️⃣ Load and validate user
        // --------------------------------------------------
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("ChangePasswordOrchestrator: user not found email={}", email);
                    return new UserNotFoundException("User not found");
                });

        if (!user.isActive()) {
            log.warn("ChangePasswordOrchestrator: blocked user attempted password change email={}", email);
            throw new AccountBlockedException("Your account has been blocked.");
        }

        // --------------------------------------------------
        // 4️⃣ Validate old password
        // --------------------------------------------------
        if (!passwordEncoder.matches(request.getOldPassword(), user.getPassword())) {
            log.warn("ChangePasswordOrchestrator: old password mismatch email={}", email);
            throw new InvalidCredentialsException("Old password is incorrect.");
        }

        // Prevent password reuse
        if (passwordEncoder.matches(request.getNewPassword(), user.getPassword())) {
            log.warn("ChangePasswordOrchestrator: new password same as old email={}", email);
            throw new InvalidCredentialsException("New password cannot be same as old password.");
        }

        // --------------------------------------------------
        // 5️⃣ Update password
        // --------------------------------------------------
        try {
            user.setPassword(passwordEncoder.encode(request.getNewPassword()));
            user.incrementTokenVersion();
            userRepository.save(user);

            // Invalidate all refresh tokens
            refreshTokenRepository.invalidateAllForUser(user.getId());


        } catch (Exception ex) {
            log.error("ChangePasswordOrchestrator: failed to update password email={} msg={}",
                    email, ex.getMessage(), ex);

            loginActivityService.recordFailure(email, "Password change failed", ip, userAgent);
            throw new PasswordChangeException("Unable to change password. Please try again later.");
        }

        // --------------------------------------------------
        // 6️⃣ Generate fresh tokens
        // --------------------------------------------------
        AuthenticationResult tokens = tokenService.generateTokens(user, ctx);

        // --------------------------------------------------
        // 7️⃣ Audit success (best-effort)
        // --------------------------------------------------
        try {
            loginActivityService.recordSuccess(user.getId(), email, ip, userAgent);
        } catch (Exception ex) {
            log.warn("ChangePasswordOrchestrator: failed to record success email={}", email);
        }

        log.info("ChangePasswordOrchestrator: completed successfully for ip={} and email={}", ctx.ip(), email);

        return AuthenticationResult.builder()
                .outcome(AuthOutcome.SUCCESS)
                .accessToken(tokens.getAccessToken())
                .refreshToken(tokens.getRefreshToken())
                .message("Password changed successfully")
                .user(UserResponse.from(user))
                .build();
    }
}


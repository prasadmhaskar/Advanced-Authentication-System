package com.pnm.auth.service.impl.auth;


import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthProviderType;
import com.pnm.auth.exception.custom.AccountBlockedException;
import com.pnm.auth.exception.custom.InvalidCredentialsException;
import com.pnm.auth.exception.custom.InvalidTokenException;
import com.pnm.auth.exception.custom.UserNotFoundException;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.service.login.LoginActivityService;
import com.pnm.auth.service.auth.UserValidationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserValidationServiceImpl implements UserValidationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final LoginActivityService loginActivityService;

    @Override
    public User validateUserForLogin(String email) {

        log.info("UserValidationService: validating user email={}", email);

        // -------------------------
        // 1. User exists?
        // -------------------------
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("UserValidationService: user not found email={}", email);
                    loginActivityService.recordFailure(email, "User not found");
                    return new UserNotFoundException("User not found with email: " + email);
                });

        // -------------------------
        // 2. Block OAuth users logging in via password
        // -------------------------
        if (user.getAuthProviderType() != null &&
                user.getAuthProviderType() != AuthProviderType.EMAIL) {

            log.warn("UserValidationService: OAuth user attempted password login email={}", email);
            loginActivityService.recordFailure(email, "OAuth accounts cannot use password login");

            throw new InvalidCredentialsException("OAuth users cannot login using password.");
        }

        // -------------------------
        // 3. Account blocked?
        // -------------------------
        if (!user.isActive()) {
            log.warn("UserValidationService: blocked account attempted login email={}", email);
            loginActivityService.recordFailure(email, "Blocked user login attempt");

            throw new AccountBlockedException("Your account has been blocked. Contact support.");
        }

        // -------------------------
        // 4. Email verified?
        // -------------------------
        if (!user.getEmailVerified()) {
            log.warn("UserValidationService: email not verified email={}", email);
            loginActivityService.recordFailure(email, "Email not verified");

            throw new InvalidTokenException("Verify your email to continue.");
        }

        // -------------------------
        // 5. All good → return user
        // -------------------------
        log.info("UserValidationService: user={} validated successfully", email);
        return user;
    }
}


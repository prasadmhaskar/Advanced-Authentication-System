package com.pnm.auth.service.impl.auth;


import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthProviderType;
import com.pnm.auth.exception.custom.*;
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

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("UserValidationService: user not found email={}", email);
                    loginActivityService.recordFailure(email, "User not found");
                    return new UserNotFoundException("User not found with email: " + email);
                });

        if (!user.isActive()) {
            log.warn("UserValidationService: blocked account attempted login email={}", email);
            loginActivityService.recordFailure(email, "Blocked user login attempt");

            throw new AccountBlockedException("Your account has been blocked. Contact support.");
        }

        if (!user.getEmailVerified()) {
            log.warn("UserValidationService: email not verified email={}", email);
            loginActivityService.recordFailure(email, "Email not verified");
            throw new EmailNotVerifiedException("Verify your email to continue.");
        }

        log.info("UserValidationService: user={} validated successfully", email);
        return user;
    }
}


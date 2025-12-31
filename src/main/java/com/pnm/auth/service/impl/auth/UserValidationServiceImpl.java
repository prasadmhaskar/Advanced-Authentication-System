package com.pnm.auth.service.impl.auth;


import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthProviderType;
import com.pnm.auth.exception.custom.*;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.service.login.LoginActivityService;
import com.pnm.auth.service.auth.UserValidationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.Hibernate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

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
                    return new UserNotFoundException("Invalid email or password.");
                });

        if (!user.isActive()) {
            log.warn("UserValidationService: blocked account attempted login email={}", email);
            throw new AccountBlockedException("Your account has been blocked. Contact support.");
        }

        if (!user.getEmailVerified()) {
            log.warn("UserValidationService: email not verified email={}", email);
            throw new EmailNotVerifiedException("Verify your email to continue.");
        }

        log.info("UserValidationService: user={} validated successfully", email);
        return user;
    }


    @Override
    @Transactional(readOnly = true)
    public Optional<User> findUserByEmail(String email) {
        log.info("UserValidationService: searching user email={}", email);
        Optional<User> userOpt = userRepository.findByEmail(email);

        // Initialize providers to prevent LazyInitializationException in the Orchestrator
        userOpt.ifPresent(user -> Hibernate.initialize(user.getAuthProviders()));

        return userOpt;
    }

    /**
     * Validates account status.
     * ONLY call this AFTER password verification to prevent enumeration.
     */
    @Override
    public void validateUserStatus(User user) {
        if (!user.isActive()) {
            log.warn("UserValidationService: blocked account attempted login email={}", user.getEmail());
            throw new AccountBlockedException("Your account has been blocked. Contact support.");
        }

        if (!user.getEmailVerified()) {
            log.warn("UserValidationService: email not verified email={}", user.getEmail());
            throw new EmailNotVerifiedException("Verify your email to continue.");
        }

        log.info("UserValidationService: status check passed for email={}", user.getEmail());
    }
}


package com.pnm.auth.service.impl.auth;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.exception.custom.InvalidCredentialsException;
import com.pnm.auth.service.login.LoginActivityService;
import com.pnm.auth.service.auth.PasswordAuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class PasswordAuthServiceImpl implements PasswordAuthService {

    private final PasswordEncoder passwordEncoder;
    private final LoginActivityService loginActivityService;

    @Override
    public void verifyPassword(User user, String rawPassword) {

        log.info("PasswordAuthService: verifying password for email={}", user.getEmail());

        // Check if password matches
        if (!passwordEncoder.matches(rawPassword, user.getPassword())) {

            log.warn("PasswordAuthService: password mismatch email={}", user.getEmail());
            throw new InvalidCredentialsException("Wrong password. Please enter the correct password.");
        }

        log.info("PasswordAuthService: password validated for email={}", user.getEmail());
    }
}

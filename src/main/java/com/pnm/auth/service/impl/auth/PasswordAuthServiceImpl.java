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

    private static final String DUMMY_HASH = "$2a$10$3euPcmQFCiblsZeEu5s7p.9OVHszj5j.M1/.n./6.1./0.1.1.1.";

    @Override
    public void verifyPassword(User userOrNull, String rawPassword) {
        // 1. Handling "User Not Found" (Timing Attack Mitigation)
        if (userOrNull == null) {
            log.warn("PasswordAuthService: User not found, performing dummy hash check to prevent timing attacks.");
            // Burn CPU time matching against dummy hash
            passwordEncoder.matches(rawPassword, DUMMY_HASH);
            throw new InvalidCredentialsException("Invalid email or password.");
        }

        log.info("PasswordAuthService: verifying password for email={}", userOrNull.getEmail());

        // 2. Handling "Wrong Password"
        if (!passwordEncoder.matches(rawPassword, userOrNull.getPassword())) {
            log.warn("PasswordAuthService: password mismatch email={}", userOrNull.getEmail());
            throw new InvalidCredentialsException("Invalid email or password.");
        }

        log.info("PasswordAuthService: password validated for email={}", userOrNull.getEmail());
    }
}

package com.pnm.auth.service.impl.auth;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.exception.custom.InvalidCredentialsException;
import com.pnm.auth.service.interfaces.auth.PasswordAuthService;
import com.pnm.auth.util.MaskingUtil;
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

        // If a user is null or user has no password (OAuth-only), use DUMMY_HASH.
        String realPasswordHash = (userOrNull != null) ? userOrNull.getPassword() : null;
        String hashToUse = (realPasswordHash != null) ? realPasswordHash : DUMMY_HASH;

        // Handle null raw password safely
        String passwordToCheck = (rawPassword != null) ? rawPassword : "";

        // This runs regardless of whether the user exists or has a password.
        boolean matches = passwordEncoder.matches(passwordToCheck, hashToUse);

        // Validate result

        if (userOrNull == null) {
            log.debug("PasswordAuthService: User not found (execution time normalized)");
            throw new InvalidCredentialsException("Invalid email or password.");
        }

        if (realPasswordHash == null) {
            // Treat OAuth-only users exactly like wrong passwords.
            // Do not reveal that the account exists.
            log.debug("PasswordAuthService: User exists but has no password (OAuth-only). Rejecting.");
            throw new InvalidCredentialsException("Invalid email or password.");
        }

        if (!matches) {
            log.warn("PasswordAuthService: Password mismatch for email={}", MaskingUtil.maskEmail(userOrNull.getEmail()));
            throw new InvalidCredentialsException("Invalid email or password.");
        }

        log.info("PasswordAuthService: Password verified for email={}", MaskingUtil.maskEmail(userOrNull.getEmail()));
    }
}
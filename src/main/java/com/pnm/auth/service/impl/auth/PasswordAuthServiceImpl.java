package com.pnm.auth.service.impl.auth;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.exception.custom.InvalidCredentialsException;
import com.pnm.auth.service.auth.PasswordAuthService;
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

    // Pre-calculated BCrypt hash (cost 10) to ensure constant timing for invalid users
    private static final String DUMMY_HASH = "$2a$10$3euPcmQFCiblsZeEu5s7p.9OVHszj5j.M1/.n./6.1./0.1.1.1.";

    @Override
    public void verifyPassword(User userOrNull, String rawPassword) {

        // 1. Determine which hash to use (Real or Dummy)
        // If user is null OR user has no password (OAuth-only), use DUMMY_HASH.
        String realPasswordHash = (userOrNull != null) ? userOrNull.getPassword() : null;
        String hashToUse = (realPasswordHash != null) ? realPasswordHash : DUMMY_HASH;

        // 2. Handle null raw password safely
        String passwordToCheck = (rawPassword != null) ? rawPassword : "";

        // 3. EXECUTE HASH (Blocking Operation: ~100ms)
        // This runs regardless of whether the user exists or has a password.
        boolean matches = passwordEncoder.matches(passwordToCheck, hashToUse);

        // 4. Validate Results (After time cost is paid)

        if (userOrNull == null) {
            log.debug("PasswordAuthService: User not found (execution time normalized)");
            throw new InvalidCredentialsException("Invalid email or password.");
        }

        if (realPasswordHash == null) {
            // "Hardcore" Fix: Treat OAuth-only users exactly like wrong passwords.
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
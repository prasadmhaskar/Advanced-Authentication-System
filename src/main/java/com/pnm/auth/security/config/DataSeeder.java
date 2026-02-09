package com.pnm.auth.security.config;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthProviderType;
import com.pnm.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
public class DataSeeder implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public void run(String... args) {
        seedAdmin();
        seedUser();
    }

    private void seedAdmin() {
        if (userRepository.findByEmail("admin@demo.com").isEmpty()) {
            User admin = new User();
            admin.setFullName("Demo Admin");
            String email = "admin@demo.com";
            admin.setEmail(email);
            admin.setPassword(passwordEncoder.encode("Admin@123"));
            admin.setRoles(List.of("ROLE_USER", "ROLE_ADMIN"));
            admin.setEmailVerified(true);
            admin.setMfaEnabled(false);
            admin.linkProvider(AuthProviderType.EMAIL, email);
            admin.setCreatedAt(LocalDateTime.now());
            admin.incrementTokenVersion();

            userRepository.save(admin);
            log.info("DataSeeder: Created 'admin@demo.com' password: 'Admin@123'");
        }
    }

    private void seedUser() {
        if (userRepository.findByEmail("user@demo.com").isEmpty()) {
            User user = new User();
            user.setFullName("Demo User");
            String email = "user@demo.com";
            user.setEmail(email);
            user.setPassword(passwordEncoder.encode("User@123"));
            user.setRoles(Collections.singletonList("ROLE_USER"));
            user.setEmailVerified(true);
            user.setMfaEnabled(false);
            user.linkProvider(AuthProviderType.EMAIL, email);
            user.setCreatedAt(LocalDateTime.now());
            user.incrementTokenVersion();

            userRepository.save(user);
            log.info("DataSeeder: Created 'user@demo.com' password: 'User@123'");
        }
    }
}
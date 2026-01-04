package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuditAction;
import com.pnm.auth.exception.custom.InvalidCredentialsException;
import com.pnm.auth.exception.custom.UserNotFoundException;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.service.auth.UserPersistenceService;
import com.pnm.auth.util.Audit;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Slf4j
@RequiredArgsConstructor
public class AccountDeleteOrchestratorImpl implements AccountDeleteOrchestrator{

    private final UserRepository userRepository;
    private final UserPersistenceService userPersistenceService; // Logic moved here
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    @Audit(action = AuditAction.SELF_DELETE, description = "User deleted his account", targetUserArgIndex = 0)
    public void deleteMyAccount(Long userId, String password) {
        log.info("UserService: User {} requested account deletion", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        // 🚨 SECURITY CHECK: Re-Authentication
        // If the user has a password (not pure OAuth), they MUST prove it's them.
        if (user.getPassword() != null) {
            if (password == null || !passwordEncoder.matches(password, user.getPassword())) {
                log.warn("UserService: Deletion failed. Invalid password for user {}", userId);
                throw new InvalidCredentialsException("Incorrect password. Account deletion aborted.");
            }
        }

        // Execute the shared Hard Delete logic
        userPersistenceService.deleteUserPermanently(userId);

        log.info("UserService: User {} deleted their own account successfully", userId);
    }
}

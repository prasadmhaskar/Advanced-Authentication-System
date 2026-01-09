package com.pnm.auth.orchestrator.auth.impl;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuditAction;
import com.pnm.auth.dto.request.DeleteAccountRequest;
import com.pnm.auth.exception.custom.InvalidCredentialsException;
import com.pnm.auth.exception.custom.UserNotFoundException;
import com.pnm.auth.orchestrator.auth.DeleteAccountOrchestrator;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.service.auth.UserPersistenceService;
import com.pnm.auth.util.Audit;
import com.pnm.auth.util.AuthUtil;
import com.pnm.auth.web.context.RequestContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@RequiredArgsConstructor
@Service
public class DeleteAccountOrchestratorImpl implements DeleteAccountOrchestrator {
    private final UserRepository userRepository;
    private final UserPersistenceService userPersistenceService;
    private final PasswordEncoder passwordEncoder;
    private final AuthUtil authUtil;

    @Transactional
    @Audit(action = AuditAction.SELF_DELETE, description = "User deleted his account", targetUserArgIndex = 0)
    public void deleteMyAccount(DeleteAccountRequest request, RequestContext ctx) {

        log.info("DeleteAccountOrchestrator: started ip={}", ctx.ip());

        Long userId = authUtil.getCurrentUserId();
        String password = request.getPassword();

        log.info("DeleteAccountOrchestrator: User with userId={}",userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        // If the user has a password, they must prove it's them.
        if (user.getPassword() != null) {
            if (password == null || !passwordEncoder.matches(password, user.getPassword())) {
                log.warn("DeleteAccountOrchestrator: Deletion failed. Invalid password for user {}", userId);
                throw new InvalidCredentialsException("Incorrect password. Account deletion aborted.");
            }
        }

        // Deletes all data from all repositories related to this user
        userPersistenceService.deleteUserPermanently(userId);

        log.info("DeleteAccountOrchestrator: finished ip={} User with userId={} deleted their own account successfully",ctx.ip(), userId);
    }
}

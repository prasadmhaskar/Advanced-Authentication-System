package com.pnm.auth.orchestrator.auth.impl;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuditAction;
import com.pnm.auth.dto.request.DeleteAccountRequest;
import com.pnm.auth.exception.custom.InvalidCredentialsException;
import com.pnm.auth.exception.custom.UserNotFoundException;
import com.pnm.auth.orchestrator.auth.DeleteAccountOrchestrator;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.service.auth.UserPersistenceService;
import com.pnm.auth.service.impl.cache.CacheManagementService;
import com.pnm.auth.util.Audit;
import com.pnm.auth.util.AuthUtil;
import com.pnm.auth.util.BlacklistedTokenStore;
import com.pnm.auth.util.JwtUtil;
import com.pnm.auth.web.context.RequestContext;
import jakarta.servlet.http.HttpServletRequest;
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
    private final JwtUtil jwtUtil;
    private final BlacklistedTokenStore blacklistedTokenStore;
    private final CacheManagementService cacheManagementService;

    @Transactional
    @Audit(action = AuditAction.SELF_DELETE, description = "User deleted his account", targetUserArgIndex = 0)
    @Override
    public void deleteMyAccount(DeleteAccountRequest request, HttpServletRequest httpServletRequest) {

        log.info("DeleteAccountOrchestrator: started");

        Long userId = AuthUtil.getCurrentUserId();
        String password = request.getPassword();

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        // If the user has a password, they must prove it's them.
        if (user.getPassword() != null && (password == null || !passwordEncoder.matches(password, user.getPassword()))) {
                log.warn("DeleteAccountOrchestrator: Deletion failed. Invalid password for user {}", userId);
                throw new InvalidCredentialsException("Incorrect password. Account deletion aborted.");
            }

        // Blacklist the token used for this request
        String accessToken = jwtUtil.resolveToken(httpServletRequest);
        if (accessToken != null) {
            long expirationTimestamp = jwtUtil.getExpirationTimestamp(accessToken);
            blacklistedTokenStore.blacklistToken(accessToken, expirationTimestamp);
        }

        // Deletes all data from all repositories related to this user
        userPersistenceService.deleteUserPermanently(userId);

        // Delete user details from cache
        cacheManagementService.evictUserFromCache(user.getEmail());

        log.info("DeleteAccountOrchestrator: finished and User with userId={} deleted their own account successfully", userId);
    }
}
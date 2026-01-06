package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.response.UserDetailsResponse;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.exception.custom.AccountBlockedException;
import com.pnm.auth.exception.custom.InvalidTokenException;
import com.pnm.auth.exception.custom.UserNotFoundException;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.util.AuthUtil;
import com.pnm.auth.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserContextOrchestratorImpl implements UserContextOrchestrator {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final AuthUtil authUtil;

    @Override
    @Transactional(readOnly = true)
    public UserDetailsResponse getCurrentUser() {

        log.info("UserContextOrchestrator: fetching user context");

        String email = authUtil.getCurrentEmail();

        log.debug("UserContextOrchestrator: extracted email={}", email);

        // 4️⃣ Load user
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("UserContextOrchestrator: user not found email={}", email);
                    return new UserNotFoundException("User not found");
                });

        // 5️⃣ Active check
        if (!user.isActive()) {
            log.warn("UserContextOrchestrator: blocked user requested /me email={}", email);
            throw new AccountBlockedException("Your account has been blocked");
        }

        // 6️⃣ Build response DTO
        return UserDetailsResponse.fromEntity(user);
    }
}


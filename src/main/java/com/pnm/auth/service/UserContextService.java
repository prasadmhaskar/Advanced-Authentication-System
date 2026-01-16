package com.pnm.auth.service;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.dto.response.UserDetailsResponse;
import com.pnm.auth.exception.custom.AccountBlockedException;
import com.pnm.auth.exception.custom.UserNotFoundException;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.util.AuthUtil;
import com.pnm.auth.web.context.RequestContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserContextService {

    private final UserRepository userRepository;

    @Transactional(readOnly = true)
    public UserDetailsResponse getCurrentUser() {

        log.info("UserContextService: started");

        String email = AuthUtil.getCurrentEmail();

        log.debug("UserContextService: extracted email={}", email);

        // Load user
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("UserContextService: user not found email={}", email);
                    return new UserNotFoundException("User not found");
                });

        // Active check
        if (!user.isActive()) {
            log.warn("UserContextService: blocked user requested /me email={}", email);
            throw new AccountBlockedException("Your account has been blocked");
        }

        log.info("UserContextService: finished for email={}", email);

        return UserDetailsResponse.fromEntity(user);
    }

}

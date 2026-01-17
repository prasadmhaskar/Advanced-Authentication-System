package com.pnm.auth.service.impl.user;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.util.MaskingUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    // value: name of the cache map in Redis
    // key: the unique identifier
    // unless: don't cache null results (prevents caching "user not found" errors forever)
    @Override
    @Cacheable(value = "user_details", key = "#email", unless = "#result == null")
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        log.info("UserDetailsServiceImpl: DB HIT for email={}", email);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("UserDetailsServiceImpl: User not found email={}", email);
                    return new UsernameNotFoundException("User not found with email: " + MaskingUtil.maskEmail(email));
                });

        return new UserDetailsImpl(user);
    }
}
package com.pnm.auth.security;

import com.pnm.auth.entity.User;
import com.pnm.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        log.info("UserDetailsServiceImpl.loadUserByUsername: Started for email={}", email);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("UserDetailsServiceImpl: User not found email={}", email);
                    return new UsernameNotFoundException("User not found with email: " + email);
                });

        log.info("UserDetailsServiceImpl: User found email={} roles={}", user.getEmail(), user.getRoles());

        UserDetailsImpl details = new UserDetailsImpl(user);

        log.info("UserDetailsServiceImpl.loadUserByUsername: Completed for email={}", email);

        return details;
    }

}


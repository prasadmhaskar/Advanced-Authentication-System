package com.pnm.auth.service.impl;

import com.pnm.auth.entity.LoginActivity;
import com.pnm.auth.entity.User;
import com.pnm.auth.repository.LoginActivityRepository;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.service.LoginActivityService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import java.time.LocalDateTime;
import java.util.Optional;


@Service
@RequiredArgsConstructor
@Slf4j
public class LoginActivityServiceImpl implements LoginActivityService {

    private final UserRepository userRepository;
    private final LoginActivityRepository loginActivityRepository;

    @Override
    public void recordSuccess(Long userId, String email, String ip, String userAgent) {

        log.info("LoginActivityService.recordSuccess(): user={} ip={}", email, ip);

        User user = userRepository.findById(userId).orElse(null);

        LoginActivity activity = LoginActivity.builder()
                .user(user)
                .email(email)
                .ipAddress(ip)
                .userAgent(userAgent)
                .status("SUCCESS")
                .message("Login successful")
                .createdAt(LocalDateTime.now())
                .build();

        loginActivityRepository.save(activity);
    }

    @Override
    public void recordFailure(String email, String ip, String userAgent, String message) {

        log.warn("LoginActivityService.recordFailure(): email={} ip={} reason={}", email, ip, message);

        LoginActivity activity = LoginActivity.builder()
                .email(email)
                .ipAddress(ip)
                .userAgent(userAgent)
                .status("FAILED")
                .message(message)
                .createdAt(LocalDateTime.now())
                .build();

        loginActivityRepository.save(activity);
    }

}

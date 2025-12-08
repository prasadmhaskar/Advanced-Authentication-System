package com.pnm.auth.service.impl;

import com.pnm.auth.entity.LoginActivity;
import com.pnm.auth.entity.User;
import com.pnm.auth.exception.ResourceNotFoundException;
import com.pnm.auth.repository.LoginActivityRepository;
import com.pnm.auth.repository.TrustedDeviceRepository;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.service.IpMonitoringService;
import com.pnm.auth.service.LoginActivityService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;


@Service
@RequiredArgsConstructor
@Slf4j
public class LoginActivityServiceImpl implements LoginActivityService {

    private final UserRepository userRepository;
    private final LoginActivityRepository loginActivityRepository;
    private final IpMonitoringService ipMonitoringService;
    private final TrustedDeviceRepository trustedDeviceRepository;

    // ---------------------------------------------
    // SUCCESS
    // ---------------------------------------------
    @Transactional
    @Override
    public void recordSuccess(Long userId, String email) {

        log.info("LoginActivityService.recordSuccess(): started userId={} email={}", userId, email);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found for id=" + userId));

        String ip = MDC.get("ip");
        String userAgent = MDC.get("userAgent");

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

        // ---- ADD IP MONITORING ----
        ipMonitoringService.recordLogin(userId, ip, userAgent);

        log.info("LoginActivityService.recordSuccess(): completed userId={} email={}", userId, email);
    }

    // ---------------------------------------------
    // FAILURE
    // ---------------------------------------------
    @Transactional
    @Override
    public void recordFailure(String email, String message) {

        String ip = MDC.get("ip");
        String userAgent = MDC.get("userAgent");

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


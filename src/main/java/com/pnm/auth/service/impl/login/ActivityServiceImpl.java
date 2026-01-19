package com.pnm.auth.service.impl.login;

import com.pnm.auth.domain.entity.LoginActivity;
import com.pnm.auth.repository.LoginActivityRepository;
import com.pnm.auth.service.interfaces.login.ActivityService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;


@Service
@RequiredArgsConstructor
@Slf4j
public class ActivityServiceImpl implements ActivityService {

    private final LoginActivityRepository loginActivityRepository;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    @Override
    public void recordSuccess(Long userId, String email, String ip, String userAgent, String message) {

        log.info("ActivityService.recordSuccess(): started userId={} email={}", userId, email);

        LoginActivity activity = LoginActivity.builder()
                .userId(userId)
                .email(email)
                .ipAddress(ip)
                .userAgent(userAgent)
                .status("SUCCESS")
                .message(message)
                .createdAt(LocalDateTime.now())
                .build();

        loginActivityRepository.save(activity);


        log.info("ActivityService.recordSuccess(): completed userId={} email={}", userId, email);
    }

    @Transactional
    @Override
    public void recordFailure(Long userId, String email, String message, String ip, String userAgent) {

        log.warn("ActivityService.recordFailure(): started email={} ip={} reason={}", email, ip, message);

        LoginActivity activity = LoginActivity.builder()
                .userId(userId)
                .email(email)
                .ipAddress(ip)
                .userAgent(userAgent)
                .status("FAILED")
                .message(message)
                .createdAt(LocalDateTime.now())
                .build();

        loginActivityRepository.save(activity);

        log.warn("ActivityService.recordFailure(): completed email={} ip={} reason={}", email, ip, message);

    }

}


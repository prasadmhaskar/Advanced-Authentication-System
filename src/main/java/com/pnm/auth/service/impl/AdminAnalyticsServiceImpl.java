package com.pnm.auth.service.impl;

import com.pnm.auth.dto.response.AdminAnalyticsResponse;
import com.pnm.auth.repository.UserIpLogRepository;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.service.AdminAnalyticsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class AdminAnalyticsServiceImpl implements AdminAnalyticsService {

    private final UserRepository userRepository;
    private final UserIpLogRepository userIpLogRepository;

    @Override
    public AdminAnalyticsResponse getAnalytics() {

        log.info("AdminAnalyticsService.getAnalytics(): started");

        long totalUsers = userRepository.countAllUsers();
        long activeUsers = userRepository.countActiveUsers();
        long blockedUsers = userRepository.countBlockedUsers();
        long mfaUsers = userRepository.countMfaEnabledUsers();

        LocalDateTime now = LocalDateTime.now();
        LocalDateTime todayStart = now.toLocalDate().atStartOfDay();
        LocalDateTime last7Days = now.minusDays(7);

        long newUsersToday = userRepository.countUsersCreatedAfter(todayStart);
        long newUsersLast7Days = userRepository.countUsersCreatedAfter(last7Days);

        long suspiciousToday = userIpLogRepository.countSuspiciousSince(todayStart);
        long suspiciousLast7Days = userIpLogRepository.countSuspiciousSince(last7Days);

        long highRisk = userIpLogRepository.countHighRiskSince(last7Days);

        AdminAnalyticsResponse response = AdminAnalyticsResponse.builder()
                .totalUsers(totalUsers)
                .activeUsers(activeUsers)
                .blockedUsers(blockedUsers)
                .mfaEnabledUsers(mfaUsers)
                .newUsersToday(newUsersToday)
                .newUsersLast7Days(newUsersLast7Days)
                .suspiciousLoginsToday(suspiciousToday)
                .suspiciousLoginsLast7Days(suspiciousLast7Days)
                .highRiskLoginAttempts(highRisk)
                .build();

        log.info("AdminAnalyticsService.getAnalytics(): completed");

        return response;
    }
}


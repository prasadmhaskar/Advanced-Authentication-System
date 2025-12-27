package com.pnm.auth.service.ipmonitoring;


import com.pnm.auth.dto.response.IpUsageResponse;
import com.pnm.auth.dto.response.UserIpLogResponse;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.retry.annotation.Retry;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

public interface IpMonitoringService {

    UserIpLogResponse recordLogin(Long userId, String ip, String userAgent);

    void recordFirstLogin(Long userId, String ip, String userAgent);

    UserIpLogResponse fallbackRiskScore(Long userId, String ip, String userAgent, Throwable ex);

    List<UserIpLogResponse> getRecentIpsForUser(Long userId);

    UserIpLogResponse getById(Long id);

    IpUsageResponse countIpUsage(String ipAddress);
}

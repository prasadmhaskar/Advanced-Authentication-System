package com.pnm.auth.service.interfaces.ipmonitoring;


import com.pnm.auth.dto.response.IpUsageResponse;
import com.pnm.auth.dto.response.UserIpLogResponse;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

public interface IpMonitoringService {

    UserIpLogResponse recordLogin(Long userId, String ip, String userAgent);

    void checkRegistrationEligibility(String ip, String userAgent);

    void recordRegistrationSuccess(Long userId, String ip, String userAgent);

    List<UserIpLogResponse> getRecentIpsForUser(Long userId);

    UserIpLogResponse getById(Long id);

    IpUsageResponse countIpUsage(String ipAddress);

    UserIpLogResponse fallbackRiskScore(Long userId, String ip, String userAgent, Throwable ex);
}

package com.pnm.auth.service;


import com.pnm.auth.dto.response.IpUsageResponse;
import com.pnm.auth.dto.response.UserIpLogResponse;

import java.util.List;

public interface IpMonitoringService {

    UserIpLogResponse recordLogin(Long userId, String ip, String userAgent);

    List<UserIpLogResponse> getRecentIpsForUser(Long userId);

    UserIpLogResponse getById(Long id);

    IpUsageResponse countIpUsage(String ipAddress);
}

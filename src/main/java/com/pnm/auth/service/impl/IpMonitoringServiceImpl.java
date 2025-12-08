package com.pnm.auth.service.impl;

import com.pnm.auth.dto.DeviceInfo;
import com.pnm.auth.dto.response.GeoLocationResponse;
import com.pnm.auth.dto.response.IpUsageResponse;
import com.pnm.auth.dto.response.UserIpLogResponse;
import com.pnm.auth.entity.UserIpLog;
import com.pnm.auth.exception.ResourceNotFoundException;
import com.pnm.auth.repository.TrustedDeviceRepository;
import com.pnm.auth.repository.UserIpLogRepository;
import com.pnm.auth.service.GeoIpService;
import com.pnm.auth.service.IpMonitoringService;
import com.pnm.auth.util.UserAgentParser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class IpMonitoringServiceImpl implements IpMonitoringService {

    private final UserIpLogRepository repo;
    private final GeoIpService geoIpService;
    private final TrustedDeviceRepository trustedDeviceRepository;


    // -------------------------------------------------------
    // Record Login with Risk Analysis (Option B)
    // -------------------------------------------------------
    @Override
    @Transactional
    public UserIpLogResponse recordLogin(Long userId, String ip, String userAgent) {

        log.info("IpMonitoringService.recordLogin(): started userId={} ip={}", userId, ip);

        if (userId == null || ip == null) {
            log.warn("IpMonitoringService.recordLogin(): invalid parameters userId={} ip={}", userId, ip);
            return null;
        }

        // ---------------------------
        // 1) Known IP / Device checks
        // ---------------------------
        boolean knownIp = repo.existsByUserIdAndIpAddress(userId, ip);

        // Parse device info from user-agent
        DeviceInfo deviceInfo = UserAgentParser.parse(userAgent);
        String deviceSignature = deviceInfo.getSignature();

        boolean trustedDevice = trustedDeviceRepository
                .existsByUserIdAndDeviceSignatureAndActiveTrue(userId, deviceSignature);

        // ---------------------------
        // 2) Previous login for impossible travel
        // ---------------------------
        UserIpLog lastLogin = repo.findTop1ByUserIdOrderByLoginTimeDesc(userId);

        // ---------------------------
        // 3) Multi-account intelligence
        // ---------------------------
        int accountsUsingIp = repo.countByIpAddress(ip);
        int accountsUsingDevice = deviceSignature != null
                ? repo.countByDeviceSignature(deviceSignature)
                : 0;

        // ---------------------------
        // 4) Geo IP lookup
        // ---------------------------
        GeoLocationResponse geo = geoIpService.lookup(ip);
        String countryCode = geo != null ? geo.getCountryCode() : null;
        String city = geo != null ? geo.getCity() : null;

        // ---------------------------
        // 5) Risk scoring
        // ---------------------------
        int riskScore = 0;
        List<String> reasons = new ArrayList<>();

// Trusted/untrusted device
        if (trustedDevice) {
            riskScore -= 15;
            reasons.add("TRUSTED_DEVICE");
        } else {
            riskScore += 20;
            reasons.add("UNTRUSTED_DEVICE");
        }

// New IP
        if (!knownIp) {
            riskScore += 20;
            reasons.add("NEW_IP_FOR_USER");
        }

// IP used by many accounts
        if (accountsUsingIp >= 3) {
            riskScore += 30;
            reasons.add("IP_USED_BY_MULTIPLE_ACCOUNTS_" + accountsUsingIp);
        }

// Device used by many accounts
        if (deviceSignature != null && accountsUsingDevice >= 3) {
            riskScore += 40;
            reasons.add("DEVICE_USED_BY_MULTIPLE_ACCOUNTS_" + accountsUsingDevice);
        }

// Impossible travel
        if (lastLogin != null && lastLogin.getCountryCode() != null && countryCode != null
                && !lastLogin.getCountryCode().equalsIgnoreCase(countryCode)) {

            Duration diff = Duration.between(lastLogin.getLoginTime(), LocalDateTime.now());
            long minutes = Math.abs(diff.toMinutes());

            if (minutes <= 60) {
                riskScore += 50;
                reasons.add("IMPOSSIBLE_TRAVEL_FROM_" + lastLogin.getCountryCode() + "_TO_" + countryCode);
            }
        }



        boolean suspicious = riskScore >= 40;

        // ---------------------------
        // 6) Build and save entity
        // ---------------------------
        UserIpLog entity = UserIpLog.builder()
                .userId(userId)
                .ipAddress(ip)
                .userAgent(userAgent)
                .countryCode(countryCode)
                .city(city)
                .isSuspicious(suspicious)
                .riskScore(riskScore)
                .riskReason(String.join(",", reasons))
                .deviceSignature(deviceSignature)
                .deviceType(deviceInfo.getDeviceType())
                .deviceName(deviceInfo.getDeviceName())
                .build();

        UserIpLog saved = repo.save(entity);

        if (suspicious) {
            log.warn("IpMonitoringService.recordLogin(): suspicious login userId={} ip={} device={} riskScore={} reasons={}",
                    userId, ip, deviceInfo.getDeviceName(), riskScore, entity.getRiskReason());
        } else {
            log.info("IpMonitoringService.recordLogin(): normal login userId={} ip={} device={}",
                    userId, ip, deviceInfo.getDeviceName());
        }

        log.info("IpMonitoringService.recordLogin(): completed userId={} ip={}", userId, ip);

        return UserIpLogResponse.fromEntity(saved);
    }


    // -------------------------------------------------------
    // Recent IPs
    // -------------------------------------------------------
    @Override
    @Transactional(readOnly = true)
    public List<UserIpLogResponse> getRecentIpsForUser(Long userId) {

        log.info("IpMonitoringService.getRecentIpsForUser(): started userId={}", userId);

        List<UserIpLogResponse> result = repo.findTop10ByUserIdOrderByLoginTimeDesc(userId)
                .stream()
                .map(UserIpLogResponse::fromEntity)
                .collect(Collectors.toList());

        log.info("IpMonitoringService.getRecentIpsForUser(): returning {} entries for userId={}",
                result.size(), userId);

        return result;
    }

    // -------------------------------------------------------
    // Single entry
    // -------------------------------------------------------
    @Override
    @Transactional(readOnly = true)
    public UserIpLogResponse getById(Long id) {

        log.info("IpMonitoringService.getById(): started id={}", id);

        UserIpLog entity = repo.findById(id)
                .orElseThrow(() -> {
                    log.warn("IpMonitoringService.getById(): not found id={}", id);
                    return new ResourceNotFoundException("IP log entry not found with id=" + id);
                });

        log.info("IpMonitoringService.getById(): completed id={}", id);

        return UserIpLogResponse.fromEntity(entity);
    }

    // -------------------------------------------------------
    // IP usage
    // -------------------------------------------------------
    @Override
    @Transactional(readOnly = true)
    public IpUsageResponse countIpUsage(String ip) {

        log.info("IpMonitoringService.countIpUsage(): started ip={}", ip);

        int count = repo.countByIpAddress(ip);

        log.info("IpMonitoringService.countIpUsage(): ip={} used by {} accounts", ip, count);

        return IpUsageResponse.builder()
                .ipAddress(ip)
                .accountCount(count)
                .build();
    }
}

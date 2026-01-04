package com.pnm.auth.service.impl.ipmonitoring;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.dto.result.DeviceInfoResult;
import com.pnm.auth.dto.response.GeoLocationResponse;
import com.pnm.auth.dto.response.IpUsageResponse;
import com.pnm.auth.dto.response.UserIpLogResponse;
import com.pnm.auth.domain.entity.UserIpLog;
import com.pnm.auth.exception.custom.RegistrationFailedException;
import com.pnm.auth.exception.custom.ResourceNotFoundException;
import com.pnm.auth.repository.TrustedDeviceRepository;
import com.pnm.auth.repository.UserIpLogRepository;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.service.geolocation.GeoIpService;
import com.pnm.auth.service.ipmonitoring.IpMonitoringService;
import com.pnm.auth.util.UserAgentParser;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.retry.annotation.Retry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
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
    private final UserRepository userRepository;

    @Value("${auth.risk.threshold.high}")
    private int highRiskScore;

    @Value("${auth.risk.threshold.medium}")
    private int mediumRiskScore;


    // -------------------------------------------------------
    // Record Login with Risk Analysis (Option B)
    // -------------------------------------------------------
    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    @Retry(name = "ipMonitoringRetry")
    @CircuitBreaker(name = "ipMonitoringCB", fallbackMethod = "fallbackRiskScore")
    public UserIpLogResponse recordLogin(Long userId, String ip, String userAgent) {

        log.info("IpMonitoringService.recordLogin(): started userId={} ip={}", userId, ip);

        if (userId == null || ip == null) {
            log.warn("IpMonitoringService.recordLogin(): invalid parameters userId={} ip={}", userId, ip);
            return null;
        }

        String userEmail = userRepository.findById(userId)
                .map(User::getEmail)
                .orElse("UNKNOWN_OR_DELETED");

        // ---------------------------
        // 1) Known IP / Device checks
        // ---------------------------
        boolean knownIp = repo.existsByUserIdAndIpAddress(userId, ip);

        // Parse device info from user-agent
        DeviceInfoResult deviceInfoResult = UserAgentParser.parse(userAgent);
        String deviceSignature = deviceInfoResult.getSignature();

        boolean trustedDevice = trustedDeviceRepository
                .existsByUserIdAndDeviceSignatureAndActiveTrue(userId, deviceSignature);

        // ---------------------------
        // 2) Previous login for impossible travel
        // ---------------------------
        UserIpLog lastLogin = repo.findTop1ByUserIdOrderByLoginTimeDesc(userId);

        // ---------------------------
        // 3) Multi-account intelligence
        // ---------------------------
        int accountsUsingIp = repo.countDistinctUsersByIp(ip);
        int accountsUsingDevice = deviceSignature != null
                ? repo.countDistinctUsersByDevice(deviceSignature)
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

        riskScore = Math.max(riskScore, 0);

        boolean suspicious = riskScore >= mediumRiskScore;

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
                .deviceType(deviceInfoResult.getDeviceType())
                .deviceName(deviceInfoResult.getDeviceName())
                .loginTime(LocalDateTime.now())
                .build();

        UserIpLog saved = repo.save(entity);

        if (suspicious) {
            log.warn("IpMonitoringService.recordLogin(): suspicious login userId={} ip={} device={} riskScore={} reasons={}",
                    userId, ip, deviceInfoResult.getDeviceName(), riskScore, entity.getRiskReason());
        } else {
            log.info("IpMonitoringService.recordLogin(): normal login userId={} ip={} device={}",
                    userId, ip, deviceInfoResult.getDeviceName());
        }

        log.info("IpMonitoringService.recordLogin(): completed userId={} ip={}", userId, ip);

        return UserIpLogResponse.fromEntity(saved, userEmail);
    }

@Transactional(readOnly = true)
@Override
public void checkRegistrationEligibility(String ip, String userAgent) {
    if (ip == null) return;

    // 2. Check Device Limit
//    DeviceInfoResult deviceInfo = UserAgentParser.parse(userAgent);
//    String signature = deviceInfo.getSignature();
//
//    if (signature != null) {
//        int accountsUsingDevice = repo.countDistinctUsersByDevice(signature);
//        //This is just a sample code for restricting multiple users per device. We have kept limit to 20 because,
//        // we have added basic UserAgentParser logic hence, different clients can have same device signature.
//        // In future we can replace this with frontEnd fingerprint library which generates unique hash for different users.
//        if (accountsUsingDevice >= 20) {
//            log.warn("Registration blocked: Device {} has already created {} accounts.", signature, accountsUsingDevice);
//            throw new RegistrationFailedException("Registration limit reached for this device.");
//        }
//    }

    // 1. Check IP Limit
    // CRITICAL: This query must only count DISTINCT emails that were SUCCESSFUL.
    // Ensure your repository query handles this correctly.
    int accountsUsingIp = repo.countDistinctUsersByIp(ip);

    if (accountsUsingIp >= 20) {
        //Same here also, different users using same public network will have same public ip. Hence we have kept limit to 20.
        log.warn("Registration blocked: IP {} has already created {} accounts.", ip, accountsUsingIp);
        throw new RegistrationFailedException("Registration limit reached for this ip.");
    }

}

    @Transactional
    @Override
    public void recordRegistrationSuccess(Long userId, String ip, String userAgent) {
        // This runs ONLY after the user is successfully created.

        DeviceInfoResult deviceInfo = UserAgentParser.parse(userAgent);
        GeoLocationResponse geo = geoIpService.lookup(ip); // Acceptable latency here, or move to @Async

        UserIpLog entity = UserIpLog.builder()
                .userId(userId)
                .ipAddress(ip)
                .userAgent(userAgent)
                .countryCode(geo != null ? geo.getCountryCode() : null)
                .city(geo != null ? geo.getCity() : null)
                .deviceSignature(deviceInfo.getSignature())
                .deviceType(deviceInfo.getDeviceType())
                .deviceName(deviceInfo.getDeviceName())
                .loginTime(LocalDateTime.now())
                .isSuspicious(false) // It's successful, so not suspicious by definition
                .build();

        repo.save(entity);
        log.info("IpMonitoring: Recorded new account creation for userId={} ip={}", userId, ip);
    }



    @Override
    public UserIpLogResponse fallbackRiskScore(Long userId, String ip, String userAgent, Throwable ex) {

        log.error("ipMonitoringService fallback triggered for userId={}, ip={}, reason={}",
                userId, ip, ex.getMessage());

        UserIpLogResponse userIpLogResponse = new UserIpLogResponse();
        userIpLogResponse.setRiskScore(50);
        userIpLogResponse.setRiskReason("monitoring_unavailable_caution");
        return userIpLogResponse;

    }



    // -------------------------------------------------------
    // Recent IPs
    // -------------------------------------------------------
    @Override
    @Transactional(readOnly = true)
    public List<UserIpLogResponse> getRecentIpsForUser(Long userId) {

        log.info("IpMonitoringService.getRecentIpsForUser(): started userId={}", userId);

        String userEmail = userRepository.findById(userId)
                .map(User::getEmail)
                .orElse("UNKNOWN_OR_DELETED");

        List<UserIpLogResponse> result = repo.findTop10ByUserIdOrderByLoginTimeDesc(userId)
                .stream()
                .map(logEntry -> UserIpLogResponse.fromEntity(logEntry, userEmail))
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

        String userEmail = null;
        if (entity.getUserId() != null) {
            userEmail = userRepository.findById(entity.getUserId())
                    .map(User::getEmail)
                    .orElse("UNKNOWN_OR_DELETED");
        }

        log.info("IpMonitoringService.getById(): completed id={}", id);

        return UserIpLogResponse.fromEntity(entity, userEmail);
    }

    // -------------------------------------------------------
    // IP usage
    // -------------------------------------------------------
    @Override
    @Transactional(readOnly = true)
    public IpUsageResponse countIpUsage(String ip) {

        log.info("IpMonitoringService.countIpUsage(): started ip={}", ip);

        int count = repo.countDistinctUsersByIp(ip);

        List<String> emails = repo.findDistinctEmailsByIp(
                ip,
                PageRequest.of(0, 20)
        );

        log.info("IpMonitoringService.countIpUsage(): ip={} used by {} accounts", ip, count);

        return IpUsageResponse.builder()
                .ipAddress(ip)
                .accountCount(count)
                .associatedEmails(emails)
                .build();
    }
}

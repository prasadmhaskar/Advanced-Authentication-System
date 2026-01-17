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
import com.pnm.auth.service.interfaces.geolocation.GeoIpService;
import com.pnm.auth.service.interfaces.ipmonitoring.IpMonitoringService;
import com.pnm.auth.util.UserAgentParser;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.retry.annotation.Retry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

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

    @Override
    @Transactional(readOnly = true)
    public void checkRegistrationEligibility(String ip, String userAgent) {
        if (ip == null) return;

        // Check Device Limit
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

        // Check IP Limit
        // CRITICAL: This query must only count DISTINCT emails that were SUCCESSFUL.
        // Ensure your repository query handles this correctly.
        int accountsUsingIp = repo.countDistinctUsersByIp(ip);

        if (accountsUsingIp >= 20) {
            //Same here also, different users using same public network will have same public ip. Hence we have kept limit to 20.
            log.warn("Registration blocked: IP {} has already created {} accounts.", ip, accountsUsingIp);
            throw new RegistrationFailedException("Registration limit reached for this ip.");
        }

    }


    // This runs ONLY after the user is successfully created.
    @Override
    @Async("loggingExecutor")
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordRegistrationSuccess(Long userId, String ip, String userAgent) {

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
                .isSuspicious(false)
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
                .toList();

        log.info("IpMonitoringService.getRecentIpsForUser(): returning {} entries for userId={}",
                result.size(), userId);

        return result;
    }

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


        @Override
        @Transactional(propagation = Propagation.REQUIRES_NEW)
        @Retry(name = "ipMonitoringRetry")
        @CircuitBreaker(name = "ipMonitoringCB", fallbackMethod = "fallbackRiskScore")
        public UserIpLogResponse recordLogin(Long userId, String ip, String userAgent) {

            log.info("IpMonitoringService: Starting parallel risk analysis for userId={} ip={}", userId, ip);

            if (userId == null || ip == null) return null;

            // Initial Parsing (Fast)
            DeviceInfoResult deviceInfo = UserAgentParser.parse(userAgent);
            String signature = deviceInfo.getSignature();

            // Fire All Expensive Calls in Parallel
            CompletableFuture<Boolean> knownIpFuture = CompletableFuture.supplyAsync(() ->
                    repo.existsByUserIdAndIpAddress(userId, ip));

            CompletableFuture<Boolean> trustedDeviceFuture = CompletableFuture.supplyAsync(() ->
                    trustedDeviceRepository.existsByUserIdAndDeviceSignatureAndActiveTrue(userId, signature));

            CompletableFuture<UserIpLog> lastLoginFuture = CompletableFuture.supplyAsync(() ->
                    repo.findTop1ByUserIdOrderByLoginTimeDesc(userId));

            CompletableFuture<Integer> accountsIpFuture = CompletableFuture.supplyAsync(() ->
                    repo.countDistinctUsersByIp(ip));

            CompletableFuture<Integer> accountsDeviceFuture = CompletableFuture.supplyAsync(() ->
                    signature != null ? repo.countDistinctUsersByDevice(signature) : 0);

            CompletableFuture<GeoLocationResponse> geoFuture = CompletableFuture.supplyAsync(() ->
                    geoIpService.lookup(ip));

            // Wait for all threads to complete
            CompletableFuture.allOf(
                    knownIpFuture, trustedDeviceFuture, lastLoginFuture,
                    accountsIpFuture, accountsDeviceFuture, geoFuture
            ).join();

            // Gather Results & Calculate Risk with Reasons
            RiskCalculationResult riskResult = calculateRisk(
                    knownIpFuture.join(),
                    trustedDeviceFuture.join(),
                    lastLoginFuture.join(),
                    accountsIpFuture.join(),
                    accountsDeviceFuture.join(),
                    geoFuture.join()
            );

            int riskScore = riskResult.score();
            String riskReason = String.join(",", riskResult.reasons());
            boolean suspicious = riskScore >= mediumRiskScore;

            // Build and Save Log
            UserIpLog entity = UserIpLog.builder()
                    .userId(userId)
                    .ipAddress(ip)
                    .userAgent(userAgent)
                    .countryCode(geoFuture.join() != null ? geoFuture.join().getCountryCode() : null)
                    .city(geoFuture.join() != null ? geoFuture.join().getCity() : null)
                    .isSuspicious(suspicious)
                    .riskScore(riskScore)
                    .riskReason(riskReason)
                    .deviceSignature(signature)
                    .deviceType(deviceInfo.getDeviceType())
                    .deviceName(deviceInfo.getDeviceName())
                    .loginTime(LocalDateTime.now())
                    .build();

            UserIpLog saved = repo.save(entity);

            // Fetch email for the response
            String userEmail = userRepository.findById(userId).map(User::getEmail).orElse("UNKNOWN");

            return UserIpLogResponse.fromEntity(saved, userEmail);
        }

        private RiskCalculationResult calculateRisk(
                boolean knownIp,
                boolean trustedDevice,
                UserIpLog lastLogin,
                int accountsUsingIp,
                int accountsUsingDevice,
                GeoLocationResponse geo
        ) {
            int riskScore = 0;
            List<String> reasons = new ArrayList<>();
            String currentCountry = geo != null ? geo.getCountryCode() : null;

            // Device Trust
            if (trustedDevice) {
                riskScore -= 15;
                reasons.add("TRUSTED_DEVICE");
            } else {
                riskScore += 20;
                reasons.add("UNTRUSTED_DEVICE");
            }

            // IP History
            if (!knownIp) {
                riskScore += 20;
                reasons.add("NEW_IP_FOR_USER");
            }

            // Multi-Account Checks
            if (accountsUsingIp >= 3) {
                riskScore += 30;
                reasons.add("IP_USED_BY_MULTIPLE_ACCOUNTS_" + accountsUsingIp);
            }

            if (accountsUsingDevice >= 3) {
                riskScore += 40;
                reasons.add("DEVICE_USED_BY_MULTIPLE_ACCOUNTS_" + accountsUsingDevice);
            }

            // Impossible Travel logic
            if (lastLogin != null && lastLogin.getCountryCode() != null && currentCountry != null
                    && !lastLogin.getCountryCode().equalsIgnoreCase(currentCountry)) {

                Duration diff = Duration.between(lastLogin.getLoginTime(), LocalDateTime.now());
                long minutes = Math.abs(diff.toMinutes());

                if (minutes <= 60) {
                    riskScore += 50;
                    reasons.add("IMPOSSIBLE_TRAVEL_FROM_" + lastLogin.getCountryCode() + "_TO_" + currentCountry);
                }
            }

            return new RiskCalculationResult(Math.max(riskScore, 0), reasons);
        }

        private record RiskCalculationResult(int score, List<String> reasons) {}

    }

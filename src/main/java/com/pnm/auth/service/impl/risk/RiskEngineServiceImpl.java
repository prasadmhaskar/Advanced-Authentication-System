package com.pnm.auth.service.impl.risk;

import com.pnm.auth.dto.response.UserIpLogResponse;
import com.pnm.auth.dto.result.RiskResult;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.exception.custom.HighRiskLoginException;
import com.pnm.auth.service.ipmonitoring.IpMonitoringService;
import com.pnm.auth.service.login.LoginActivityService;
import com.pnm.auth.service.login.SuspiciousLoginAlertService;
import com.pnm.auth.service.risk.RiskEngineService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class RiskEngineServiceImpl implements RiskEngineService {

    private final IpMonitoringService ipMonitoringService;
    private final LoginActivityService loginActivityService;
    private final SuspiciousLoginAlertService suspiciousLoginAlertService;

    @Override
    public RiskResult evaluateRisk(User user, String ip, String userAgent) {

        log.info("RiskEngineService: evaluating risk for email={} ip={}", user.getEmail(), ip);

        // 1) Call IP monitoring service (already has resilience)
        UserIpLogResponse response = ipMonitoringService.recordLogin(user.getId(), ip, userAgent);

        int score = response.getRiskScore();
        List<String> reasons = response.getRiskReason() != null
                ? Arrays.asList(response.getRiskReason().split(","))
                : List.of();

        log.info("RiskEngineService: riskScore={} reasons={}", score, reasons);

        // 2) HIGH RISK → Block login
        if (score >= 80) {
            return RiskResult.builder()
                    .score(score)
                    .reasons(reasons)
                    .blocked(true)
                    .otpRequired(false)
                    .build();
        }

        // 3) MEDIUM RISK → OTP required
        if (score >= 40) {
            return RiskResult.builder()
                    .score(score)
                    .reasons(reasons)
                    .blocked(false)
                    .otpRequired(true)
                    .build();
        }

        // 4) LOW RISK → Proceed normally
        return RiskResult.builder()
                .score(score)
                .reasons(reasons)
                .blocked(false)
                .otpRequired(false)
                .build();
    }

    @Override
    public RuntimeException blockHighRiskLogin(User user, RiskResult risk, String ip, String userAgent) {

        suspiciousLoginAlertService.sendHighRiskAlert(
                user,
                ip,
                userAgent,
                risk.getReasons()
        );

        loginActivityService.recordFailure(user.getEmail(), "High risk login blocked", ip, userAgent);

        return new HighRiskLoginException("Login blocked due to high risk activity.");
    }

}

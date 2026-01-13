package com.pnm.auth.service.impl.risk;

import com.pnm.auth.dto.response.UserIpLogResponse;
import com.pnm.auth.dto.result.RiskResult;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.service.ipmonitoring.IpMonitoringService;
import com.pnm.auth.service.login.LoginActivityService;
import com.pnm.auth.service.risk.RiskEngineService;
import com.pnm.auth.util.MaskingUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class RiskEngineServiceImpl implements RiskEngineService {

    private final IpMonitoringService ipMonitoringService;
    private final LoginActivityService loginActivityService;

    @Value("${auth.risk.threshold.high}")
    private int highRiskScore;

    @Value("${auth.risk.threshold.medium}")
    private int mediumRiskScore;

//    @Override
//    public RiskResult evaluateRisk(User user, String ip, String userAgent) {
//
//        log.info("RiskEngineService: evaluating risk for email={} ip={}", user.getEmail(), ip);
//
//        // 1) Call IP monitoring service (already has resilience)
//        UserIpLogResponse response = ipMonitoringService.recordLogin(user.getId(), ip, userAgent);
//
//        int score = response.getRiskScore();
//        List<String> reasons = response.getRiskReason() != null
//                ? Arrays.asList(response.getRiskReason().split(","))
//                : List.of();
//
//        log.info("RiskEngineService: riskScore={} reasons={}", score, reasons);
//
//        // 2) HIGH RISK → Block login
//        if (score >= highRiskScore) {
//            return RiskResult.builder()
//                    .score(score)
//                    .reasons(reasons)
//                    .blocked(true)
//                    .otpRequired(false)
//                    .build();
//        }
//
//        // 3) MEDIUM RISK → OTP required
//        if (score >= mediumRiskScore) {
//            return RiskResult.builder()
//                    .score(score)
//                    .reasons(reasons)
//                    .blocked(false)
//                    .otpRequired(true)
//                    .build();
//        }
//
//        // 4) LOW RISK → Proceed normally
//        return RiskResult.builder()
//                .score(score)
//                .reasons(reasons)
//                .blocked(false)
//                .otpRequired(false)
//                .build();
//    }

    @Override
    public RiskResult evaluateRisk(User user, String ip, String userAgent) {
        log.info("Evaluating risk for email={} ip={}", MaskingUtil.maskEmail(user.getEmail()), ip);

        try {
            // Calling the parallelized recordLogin
            UserIpLogResponse response = ipMonitoringService.recordLogin(user.getId(), ip, userAgent);

            int score = response.getRiskScore();
            List<String> reasons = response.getRiskReason() != null
                ? Arrays.asList(response.getRiskReason().split(","))
                : List.of();

            return RiskResult.builder()
                    .score(score)
                    .reasons(reasons)
                    .blocked(score >= highRiskScore)
                    .otpRequired(score >= mediumRiskScore && score < highRiskScore)
                    .build();

        } catch (Exception e) {
            log.error("Risk evaluation failed. Falling back to Safety MFA.", e);
            // Fail-safe: If evaluation fails, require OTP just in case
            return RiskResult.builder().score(mediumRiskScore).otpRequired(true).build();
        }
    }




}

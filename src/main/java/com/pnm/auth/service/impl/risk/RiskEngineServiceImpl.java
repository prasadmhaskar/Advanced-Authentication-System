package com.pnm.auth.service.impl.risk;

import com.pnm.auth.dto.response.UserIpLogResponse;
import com.pnm.auth.dto.result.RiskResult;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.service.interfaces.ipmonitoring.IpMonitoringService;
import com.pnm.auth.service.interfaces.login.LoginActivityService;
import com.pnm.auth.service.interfaces.risk.RiskEngineService;
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


    @Override
    public RiskResult evaluateRisk(User user, String ip, String userAgent) {
        log.info("Evaluating risk for email={} ip={}", MaskingUtil.maskEmail(user.getEmail()), ip);

        try {
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
            // If evaluation fails, require otp just in case
            return RiskResult.builder().score(mediumRiskScore).otpRequired(true).build();
        }
    }




}

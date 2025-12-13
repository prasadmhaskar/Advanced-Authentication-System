package com.pnm.auth.service.auth;

import com.pnm.auth.dto.response.RiskResponse;
import com.pnm.auth.dto.result.RiskResult;
import com.pnm.auth.entity.User;

public interface RiskEngineService {
    RiskResult evaluateRisk(User user, String ip, String userAgent);


    RuntimeException blockHighRiskLogin(User user, RiskResult risk, String ip, String userAgent);
}


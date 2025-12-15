package com.pnm.auth.service.risk;

import com.pnm.auth.dto.result.RiskResult;
import com.pnm.auth.domain.entity.User;

public interface RiskEngineService {

    RiskResult evaluateRisk(User user, String ip, String userAgent);

    RuntimeException blockHighRiskLogin(User user, RiskResult risk, String ip, String userAgent);
}


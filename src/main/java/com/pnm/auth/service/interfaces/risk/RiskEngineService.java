package com.pnm.auth.service.interfaces.risk;

import com.pnm.auth.dto.result.RiskResult;
import com.pnm.auth.domain.entity.User;

public interface RiskEngineService {

    RiskResult evaluateRisk(Long userId, String ip, String userAgent);
}


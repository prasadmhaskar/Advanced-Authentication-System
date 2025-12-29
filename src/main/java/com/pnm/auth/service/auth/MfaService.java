package com.pnm.auth.service.auth;

import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.dto.result.MfaResult;
import com.pnm.auth.domain.entity.User;

public interface MfaService {
    MfaResult handleMfaLogin(User user);
    MfaResult handleMediumRiskOtp(User user);
}


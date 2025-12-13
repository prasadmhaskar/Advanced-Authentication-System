package com.pnm.auth.service.auth;

import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.dto.result.MfaResult;
import com.pnm.auth.entity.User;

public interface MfaService {
    AuthenticationResult handleMfaLogin(User user);
    MfaResult handleMediumRiskOtp(User user);
}


package com.pnm.auth.service.auth;

import com.pnm.auth.dto.result.AuthenticationResult;

public interface RefreshTokenOrchestrator {
    AuthenticationResult refresh(String refreshToken);
}


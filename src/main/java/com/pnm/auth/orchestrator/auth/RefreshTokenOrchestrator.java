package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.result.AuthenticationResult;

public interface RefreshTokenOrchestrator {
    AuthenticationResult refresh(String refreshToken);
}


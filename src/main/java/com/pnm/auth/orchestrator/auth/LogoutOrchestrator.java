package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.request.LogoutRequest;

public interface LogoutOrchestrator {
    void logout(LogoutRequest requestBody);
}


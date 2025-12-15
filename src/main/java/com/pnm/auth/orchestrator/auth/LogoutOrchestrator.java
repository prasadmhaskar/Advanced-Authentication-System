package com.pnm.auth.orchestrator.auth;

public interface LogoutOrchestrator {
    void logout(String accessToken, String refreshToken);
}


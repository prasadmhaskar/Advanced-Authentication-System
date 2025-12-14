package com.pnm.auth.service.auth;

public interface LogoutOrchestrator {
    void logout(String accessToken, String refreshToken);
}


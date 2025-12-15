package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.request.LoginRequest;
import com.pnm.auth.dto.result.AuthenticationResult;

public interface LoginOrchestrator {
    AuthenticationResult login(LoginRequest request, String ip, String userAgent);
}

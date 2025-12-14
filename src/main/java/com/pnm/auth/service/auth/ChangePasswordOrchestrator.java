package com.pnm.auth.service.auth;

import com.pnm.auth.dto.request.ChangePasswordRequest;
import com.pnm.auth.dto.result.AuthenticationResult;

public interface ChangePasswordOrchestrator {
    AuthenticationResult changePassword(
            String accessToken,
            ChangePasswordRequest request
    );
}


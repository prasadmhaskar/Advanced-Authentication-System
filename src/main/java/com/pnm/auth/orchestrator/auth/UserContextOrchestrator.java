package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.response.UserDetailsResponse;

public interface UserContextOrchestrator {
    UserDetailsResponse getCurrentUser(String accessToken);
}


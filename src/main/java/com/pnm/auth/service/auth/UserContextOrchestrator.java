package com.pnm.auth.service.auth;

import com.pnm.auth.dto.response.UserDetailsResponse;

public interface UserContextOrchestrator {
    UserDetailsResponse getCurrentUser(String accessToken);
}


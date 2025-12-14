package com.pnm.auth.service.auth;

import com.pnm.auth.dto.request.ResetPasswordRequest;

public interface ResetPasswordOrchestrator {
    void reset(ResetPasswordRequest request);
}

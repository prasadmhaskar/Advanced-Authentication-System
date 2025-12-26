package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.request.ResetPasswordRequest;

public interface ResetPasswordOrchestrator {
    void reset(ResetPasswordRequest request, String ip, String userAgent);
}

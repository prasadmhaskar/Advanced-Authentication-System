package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.result.ForgotPasswordResult;

public interface ForgotPasswordOrchestrator {
    ForgotPasswordResult requestReset(String email);
}


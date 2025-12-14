package com.pnm.auth.service.auth;

import com.pnm.auth.dto.result.ForgotPasswordResult;

public interface ForgotPasswordOrchestrator {
    ForgotPasswordResult requestReset(String email);
}


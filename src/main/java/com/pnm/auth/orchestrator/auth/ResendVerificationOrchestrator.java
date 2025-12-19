package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.result.ResendVerificationResult;

public interface ResendVerificationOrchestrator {
    ResendVerificationResult resend(String email);
}

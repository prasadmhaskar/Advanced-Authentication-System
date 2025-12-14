package com.pnm.auth.service.auth;

import com.pnm.auth.dto.result.EmailVerificationResult;

public interface VerifyEmailOrchestrator {
    EmailVerificationResult verify(String token);
}


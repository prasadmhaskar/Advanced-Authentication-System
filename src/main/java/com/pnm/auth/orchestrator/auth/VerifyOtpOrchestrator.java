package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.request.OtpVerifyRequest;
import com.pnm.auth.dto.result.AuthenticationResult;

public interface VerifyOtpOrchestrator {
    AuthenticationResult verify(OtpVerifyRequest request, String ip, String userAgent);
}


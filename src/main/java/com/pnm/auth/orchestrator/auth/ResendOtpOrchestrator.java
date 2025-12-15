package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.request.OtpResendRequest;

public interface ResendOtpOrchestrator {
    void resend(OtpResendRequest request);
}


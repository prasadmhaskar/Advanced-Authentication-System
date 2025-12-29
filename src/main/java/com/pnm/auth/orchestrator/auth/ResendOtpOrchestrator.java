package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.request.OtpResendRequest;
import com.pnm.auth.dto.response.ResendOtpResponse;

public interface ResendOtpOrchestrator {
    ResendOtpResponse resend(OtpResendRequest request);
}


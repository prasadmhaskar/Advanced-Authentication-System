package com.pnm.auth.service.auth;

import com.pnm.auth.dto.request.OtpResendRequest;

public interface ResendOtpOrchestrator {
    void resend(OtpResendRequest request);
}


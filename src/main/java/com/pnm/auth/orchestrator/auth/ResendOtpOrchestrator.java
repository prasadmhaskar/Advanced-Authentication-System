package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.request.OtpResendRequest;
import com.pnm.auth.dto.response.ResendOtpResponse;
import com.pnm.auth.web.context.RequestContext;

public interface ResendOtpOrchestrator {
    ResendOtpResponse resend(OtpResendRequest request, RequestContext ctx);
}


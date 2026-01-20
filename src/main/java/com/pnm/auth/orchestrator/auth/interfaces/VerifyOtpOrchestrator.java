package com.pnm.auth.orchestrator.auth.interfaces;

import com.pnm.auth.dto.request.OtpVerifyRequest;
import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.web.context.RequestContext;

public interface VerifyOtpOrchestrator {
    AuthenticationResult verify(OtpVerifyRequest request, RequestContext ctx);
}


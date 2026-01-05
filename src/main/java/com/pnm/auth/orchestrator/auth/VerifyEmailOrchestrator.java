package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.result.EmailVerificationResult;
import com.pnm.auth.web.context.RequestContext;

public interface VerifyEmailOrchestrator {
//    EmailVerificationResult verify(String rawToken, String ip, String ua);
    EmailVerificationResult verify(String rawToken, RequestContext ctx);
}


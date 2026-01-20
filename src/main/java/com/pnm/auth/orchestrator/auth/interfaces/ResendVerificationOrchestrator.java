package com.pnm.auth.orchestrator.auth.interfaces;

import com.pnm.auth.dto.result.ResendVerificationResult;
import com.pnm.auth.web.context.RequestContext;

public interface ResendVerificationOrchestrator {
    ResendVerificationResult resend(String email, RequestContext ctx);
}

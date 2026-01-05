package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.request.ResetPasswordRequest;
import com.pnm.auth.web.context.RequestContext;

public interface ResetPasswordOrchestrator {
    void reset(ResetPasswordRequest request, RequestContext ctx);
}

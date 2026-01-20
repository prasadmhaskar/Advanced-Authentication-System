package com.pnm.auth.orchestrator.auth.interfaces;

import com.pnm.auth.dto.request.ResetPasswordRequest;
import com.pnm.auth.web.context.RequestContext;

public interface ResetPasswordOrchestrator {
    void resetPassword(ResetPasswordRequest request, RequestContext ctx);
}

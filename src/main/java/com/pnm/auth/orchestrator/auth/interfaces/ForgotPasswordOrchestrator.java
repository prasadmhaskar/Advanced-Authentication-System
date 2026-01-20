package com.pnm.auth.orchestrator.auth.interfaces;

import com.pnm.auth.dto.result.ForgotPasswordResult;
import com.pnm.auth.web.context.RequestContext;

public interface ForgotPasswordOrchestrator {
    ForgotPasswordResult requestReset(String email, RequestContext ctx);
}


package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.request.ChangePasswordRequest;
import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.web.context.RequestContext;

public interface ChangePasswordOrchestrator {
    AuthenticationResult changePassword(ChangePasswordRequest request, RequestContext ctx);
}


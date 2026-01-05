package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.request.LoginRequest;
import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.web.context.RequestContext;

public interface LoginOrchestrator {
    AuthenticationResult login(LoginRequest request,RequestContext ctx);
}

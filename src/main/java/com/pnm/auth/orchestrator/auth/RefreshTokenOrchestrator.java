package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.web.context.RequestContext;

public interface RefreshTokenOrchestrator {
    AuthenticationResult refresh(String refreshToken, RequestContext ctx);
}


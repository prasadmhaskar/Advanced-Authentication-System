package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.request.LogoutRequest;
import com.pnm.auth.web.context.RequestContext;
import jakarta.servlet.http.HttpServletRequest;

public interface LogoutOrchestrator {
    void logout(LogoutRequest request, HttpServletRequest httpServletRequest, RequestContext ctx);
}

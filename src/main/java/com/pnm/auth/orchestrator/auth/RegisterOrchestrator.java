package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.request.RegisterRequest;
import com.pnm.auth.dto.result.RegistrationResult;
import com.pnm.auth.web.context.RequestContext;

public interface RegisterOrchestrator {
//    RegistrationResult register(RegisterRequest request, String ip, String ua);
    RegistrationResult register(RegisterRequest request, RequestContext ctx);
}

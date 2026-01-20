package com.pnm.auth.orchestrator.auth.interfaces;

import com.pnm.auth.dto.request.RegisterRequest;
import com.pnm.auth.dto.result.RegistrationResult;
import com.pnm.auth.web.context.RequestContext;

public interface RegisterOrchestrator {
    RegistrationResult register(RegisterRequest request, RequestContext ctx);
}

package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.request.RegisterRequest;
import com.pnm.auth.dto.result.RegistrationResult;

public interface RegisterOrchestrator {
    RegistrationResult register(RegisterRequest request);
}

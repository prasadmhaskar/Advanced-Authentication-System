package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.request.DeleteAccountRequest;

public interface AccountDeleteOrchestrator {
    void deleteMyAccount(DeleteAccountRequest request);
}

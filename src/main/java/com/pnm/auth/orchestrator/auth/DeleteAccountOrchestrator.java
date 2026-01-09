package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.request.DeleteAccountRequest;
import com.pnm.auth.web.context.RequestContext;

public interface DeleteAccountOrchestrator {
    void deleteMyAccount(DeleteAccountRequest request, RequestContext ctx);
}

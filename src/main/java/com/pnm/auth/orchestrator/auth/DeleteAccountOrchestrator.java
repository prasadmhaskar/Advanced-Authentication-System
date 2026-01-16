package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.request.DeleteAccountRequest;
import jakarta.servlet.http.HttpServletRequest;

public interface DeleteAccountOrchestrator {
    void deleteMyAccount(DeleteAccountRequest request, HttpServletRequest httpServletRequest);
}

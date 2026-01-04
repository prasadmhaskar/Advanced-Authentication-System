package com.pnm.auth.orchestrator.auth;

public interface AccountDeleteOrchestrator {
    void deleteMyAccount(Long userId, String password);
}

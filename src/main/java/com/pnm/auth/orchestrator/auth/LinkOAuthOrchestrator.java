package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.request.LinkOAuthRequest;
import com.pnm.auth.dto.result.AccountLinkResult;

public interface LinkOAuthOrchestrator {
    AccountLinkResult link(LinkOAuthRequest request);
}


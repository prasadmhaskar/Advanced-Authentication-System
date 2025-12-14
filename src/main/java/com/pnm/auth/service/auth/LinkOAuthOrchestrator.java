package com.pnm.auth.service.auth;

import com.pnm.auth.dto.request.LinkOAuthRequest;

public interface LinkOAuthOrchestrator {
    void link(LinkOAuthRequest request);
}


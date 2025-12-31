package com.pnm.auth.service.auth;

import com.pnm.auth.dto.request.LinkOAuthRequest;
import com.pnm.auth.dto.result.LinkingResult;

public interface AccountLinkingService {
    LinkingResult linkAccount(LinkOAuthRequest request);
}

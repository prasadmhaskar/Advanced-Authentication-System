package com.pnm.auth.service.auth;

import com.pnm.auth.dto.request.LinkOAuthRequest;
import com.pnm.auth.dto.result.LinkingResult;
import com.pnm.auth.web.context.RequestContext;

public interface AccountLinkingService {
    LinkingResult linkAccount(LinkOAuthRequest request, RequestContext ctx);
}

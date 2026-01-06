package com.pnm.auth.service.auth;

import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.web.context.RequestContext;

public interface TokenService {
    AuthenticationResult generateTokens(User user, RequestContext ctx);
}


package com.pnm.auth.service.auth;

import com.pnm.auth.dto.request.ChangePasswordRequest;
import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.web.context.RequestContext;

public interface PasswordChangeService {
    AuthenticationResult changePassword(ChangePasswordRequest request, RequestContext ctx);
}

package com.pnm.auth.service.auth;

import com.pnm.auth.dto.request.ResetPasswordRequest;
import com.pnm.auth.web.context.RequestContext;

public interface PasswordResetService {
    void resetPassword(ResetPasswordRequest request, RequestContext ctx);
}

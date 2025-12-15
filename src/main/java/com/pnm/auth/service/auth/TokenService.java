package com.pnm.auth.service.auth;

import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.domain.entity.User;

public interface TokenService {
    AuthenticationResult generateTokens(User user);
}


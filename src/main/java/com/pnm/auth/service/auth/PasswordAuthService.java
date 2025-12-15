package com.pnm.auth.service.auth;

import com.pnm.auth.domain.entity.User;

public interface PasswordAuthService {
    void verifyPassword(User user, String rawPassword);
}


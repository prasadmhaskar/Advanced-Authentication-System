package com.pnm.auth.service.auth;

import com.pnm.auth.domain.entity.User;

public interface UserValidationService {
    User validateUserForLogin(String email);
}


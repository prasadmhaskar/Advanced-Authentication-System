package com.pnm.auth.service.auth;

import com.pnm.auth.entity.User;

public interface UserValidationService {
    User validateUserForLogin(String email);
}


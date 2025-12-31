package com.pnm.auth.service.auth;

import com.pnm.auth.domain.entity.User;

import java.util.Optional;

public interface UserValidationService {
    User validateUserForLogin(String email);

    Optional<User> findUserByEmail(String email);
    void validateUserStatus(User user);
}


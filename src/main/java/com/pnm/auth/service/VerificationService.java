package com.pnm.auth.service;

import com.pnm.auth.entity.User;

public interface VerificationService {

    String createVerificationToken(User user, String type);

    void validateToken(String token, String type);
}

package com.pnm.auth.service.impl;

import com.pnm.auth.entity.User;
import com.pnm.auth.service.VerificationService;

public class VerificationServiceImpl implements VerificationService {
    @Override
    public String createVerificationToken(User user, String type) {
        return "";
    }

    @Override
    public void validateToken(String token, String type) {

    }
}

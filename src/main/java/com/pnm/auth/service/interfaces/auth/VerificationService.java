package com.pnm.auth.service.interfaces.auth;

import com.pnm.auth.domain.entity.User;

public interface VerificationService {

    String createVerificationToken(User user, String type);

}

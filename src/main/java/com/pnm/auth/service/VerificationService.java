package com.pnm.auth.service;

import com.pnm.auth.dto.request.EmailVerificationRequest;
import com.pnm.auth.entity.User;
import jakarta.validation.Valid;

public interface VerificationService {

    String createVerificationToken(User user, String type);

    void validateToken(String token, String type);


}

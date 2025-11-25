package com.pnm.auth.service.impl;

import com.pnm.auth.service.EmailService;
import org.springframework.stereotype.Service;

@Service
public class EmailServiceImpl implements EmailService {
    @Override
    public void sendVerificationEmail(String toEmail, String token) {

    }

    @Override
    public void sendPasswordResetEmail(String toEmail, String token) {

    }
}

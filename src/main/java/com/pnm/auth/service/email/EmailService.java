package com.pnm.auth.service.email;

import java.util.concurrent.CompletableFuture;

public interface EmailService {

    CompletableFuture<Boolean> sendVerificationEmail(String toEmail, String token);

    void sendEmail(String toEmail, String subject, String body);

    void sendMfaOtpEmail(String toEmail, String otp);

    CompletableFuture<Boolean> sendSetPasswordEmail(String email, String token);
}

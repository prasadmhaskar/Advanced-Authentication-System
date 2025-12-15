package com.pnm.auth.service.email;

public interface EmailService {

    void sendVerificationEmail(String toEmail, String token);

    void sendPasswordResetEmail(String toEmail, String token);

    void sendEmail(String toEmail, String subject, String body);

    void sendMfaOtpEmail(String toEmail, String otp);
}

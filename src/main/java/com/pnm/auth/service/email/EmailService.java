package com.pnm.auth.service.email;

import com.pnm.auth.domain.entity.User;

import java.util.List;

public interface EmailService {

    void sendVerificationEmail(String toEmail, String token);

    void sendEmail(String toEmail, String subject, String body);

    void sendMfaOtpEmail(String toEmail, String otp);

    void sendSetPasswordEmail(String email, String token);

    void sendHighRiskAlert(User user, String ip, String userAgent, List<String> reasons);
}

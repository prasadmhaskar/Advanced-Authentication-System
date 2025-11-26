package com.pnm.auth.service.impl;

import com.pnm.auth.service.EmailService;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender mailSender;

    @Override
    public void sendVerificationEmail(String toEmail, String token) {
        String subject = "Verify Your Email";
        String verificationLink = "http://localhost:8080/api/auth/verify?token=" + token;

        String body = """
                Hello,
                
                Please verify your email by clicking the link below:
                """ + verificationLink;

        sendEmail(toEmail, subject, body);
    }

    @Override
    public void sendPasswordResetEmail(String toEmail, String token) {
        String subject = "Reset Your Password";
        String resetLink = "http://localhost:8080/reset-password?token=" + token;

        String body = """
                Hello,
                
                Click the link below to reset your password:
                """ + resetLink;

        sendEmail(toEmail, subject, body);
    }

    private void sendEmail(String toEmail, String subject, String body) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(toEmail);
        message.setSubject(subject);
        message.setText(body);
        message.setFrom("noreply@project1.com");
        mailSender.send(message);
    }
}


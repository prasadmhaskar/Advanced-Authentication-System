package com.pnm.auth.service.impl;

import com.pnm.auth.service.EmailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender mailSender;

    @Override
    public void sendVerificationEmail(String toEmail, String token) {

        log.info("EmailService.sendVerificationEmail: Started for email={}",toEmail);
        String subject = "Verify Your Email";
        String verificationLink = "http://localhost:8080/api/auth/verify?token=" + token;

        String body = """
                Hello,
                
                Please verify your email by clicking the link below:
                """ + verificationLink;

        sendEmail(toEmail, subject, body);
        log.info("EmailService.sendVerificationEmail: Sent verification email to {}", toEmail);

    }

    @Override
    public void sendPasswordResetEmail(String toEmail, String token) {
        log.info("EmailService.sendPasswordResetEmail: Started for email={}",toEmail);
        String subject = "Reset Your Password";
        String resetLink = "http://localhost:8080/reset-password?token=" + token;

        String body = """
                Hello,
                
                Click the link below to reset your password:
                """ + resetLink;

        sendEmail(toEmail, subject, body);
        log.info("EmailService.sendPasswordResetEmail: Sent password reset email to {}", toEmail);
    }


    @Override
    public void sendEmail(String toEmail, String subject, String body) {
        log.info("EmailService.sendEmail: Email sending to={}",toEmail);
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(toEmail);
        message.setSubject(subject);
        message.setText(body);
        message.setFrom("noreply@project1.com");
        mailSender.send(message);
        log.info("EmailService.sendEmail: Email sent to={}",toEmail);
    }

    @Override
    public void sendMfaOtpEmail(String toEmail, String otp) {

        log.info("EmailService.sendMfaOtpEmail(): sending MFA OTP to {}", toEmail);

        String subject = "Your MFA Verification Code";
        String body = "Your OTP for login is: " + otp + "\nIt will expire in 5 minutes.";

        sendEmail(toEmail, subject, body);

    }
}


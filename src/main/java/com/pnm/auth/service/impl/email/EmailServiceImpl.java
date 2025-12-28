package com.pnm.auth.service.impl.email;

import com.pnm.auth.exception.custom.EmailSendFailedException;
import com.pnm.auth.service.email.EmailService;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.retry.annotation.Retry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.concurrent.CompletableFuture;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender mailSender;

    @Override
    @Async("emailExecutor")
    @Retry(name = "emailRetry")
    @CircuitBreaker(name = "emailCB", fallbackMethod = "fallbackVerificationEmail")
    public CompletableFuture<Boolean> sendVerificationEmail(String toEmail, String token) {

        log.info("EmailService: sending verification email to={}", toEmail);

        String subject = "Verify Your Email";
        String verificationLink = "http://localhost:8080/api/auth/verify?token=" + token;

        String body = """
                Hello,

                Please verify your email by clicking the link below:
                %s
                """.formatted(verificationLink);

        sendEmail(toEmail, subject, body);
        return CompletableFuture.completedFuture(true);
    }

    @Override
    @Async("emailExecutor")
    @Retry(name = "emailRetry")
    @CircuitBreaker(name = "emailCB", fallbackMethod = "fallbackPasswordEmail")
    public CompletableFuture<Boolean> sendSetPasswordEmail(String email, String token) {

        log.info("EmailService: sending set-password email to={}", email);

        String link = "http://localhost:8080/reset-password?token=" + token;

        String subject = "Set your password";
        String body = """
                Hi,

                Click the link below to set your password:
                %s

                This link expires in 15 minutes.
                """.formatted(link);

        sendEmail(email, subject, body);
        return CompletableFuture.completedFuture(true);
    }

    @Override
    @Async("emailExecutor")
    @Retry(name = "emailRetry")
    @CircuitBreaker(name = "emailCB", fallbackMethod = "fallbackOtpEmail")
    public void sendMfaOtpEmail(String toEmail, String otp) {

        log.info("EmailService: sending MFA OTP email to={}", toEmail);

        String subject = "Your MFA Verification Code";
        String body = "Your OTP is: " + otp + " (valid for 5 minutes)";

        sendEmail(toEmail, subject, body);
    }

    // -----------------------------
    // INTERNAL SEND
    // -----------------------------
    public void sendEmail(String toEmail, String subject, String body) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(toEmail);
        message.setSubject(subject);
        message.setText(body);
        message.setFrom("noreply@project1.com");

        mailSender.send(message);
        log.info("EmailService: email sent to={}", toEmail);
    }

    // -----------------------------
    // FALLBACKS (NO THROWING!)
    // -----------------------------
    public CompletableFuture<Boolean> fallbackVerificationEmail(String email, String token, Throwable ex) {
        log.error("EmailService FALLBACK: verification email failed email={} reason={}", email, ex.getMessage(), ex);
        return CompletableFuture.completedFuture(false);
    }

    public CompletableFuture<Boolean> fallbackPasswordEmail(String email, String token, Throwable ex) {
        log.error("EmailService FALLBACK: password email failed email={} reason={}",
                email, ex.getMessage(), ex);
        return CompletableFuture.completedFuture(false);
    }

    public void fallbackOtpEmail(String email, String otp, Throwable ex) {
        log.error("EmailService FALLBACK: OTP email failed email={} reason={}",
                email, ex.getMessage(), ex);
    }
}



package com.pnm.auth.service.impl.email;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.service.email.EmailService;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.retry.annotation.Retry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender mailSender;

    @Value("${app.base-url}")
    private String baseUrl;

    @Override
    @Async("emailExecutor")
    @Retry(name = "emailRetry")
    @CircuitBreaker(name = "emailCB", fallbackMethod = "fallbackVerificationEmail")
    public void sendVerificationEmail(String toEmail, String token) {

        log.info("EmailService: sending verification email to={}", toEmail);

        String subject = "Verify Your Email";
        String verificationLink = baseUrl+ "/api/auth/verify?token=" + token;

        String body = """
                Hello,

                Please verify your email by clicking the link below:
                %s
                """.formatted(verificationLink);

        sendEmail(toEmail, subject, body);
    }

    @Override
    @Async("emailExecutor")
    @Retry(name = "emailRetry")
    @CircuitBreaker(name = "emailCB", fallbackMethod = "fallbackPasswordEmail")
    public void sendSetPasswordEmail(String email, String token) {

        log.info("EmailService: sending set-password email to={}", email);

        String link = baseUrl+ "/reset-password?token=" + token;

        String subject = "Set your password";
        String body = """
                Hi,

                Click the link below to set your password:
                %s

                This link expires in 15 minutes.
                """.formatted(link);

        sendEmail(email, subject, body);
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

    @Override
    @Async("emailExecutor")
    @Retry(name = "emailRetry")
    @CircuitBreaker(name = "emailCB", fallbackMethod = "fallbackHighRiskAlert")
    public void sendHighRiskAlert(User user, String ip, String userAgent, List<String> reasons) {

        log.warn("Sending suspicious login alert to user={} from IP={}", user.getEmail(), ip);

        String subject = "⚠ Suspicious Login Attempt Blocked";
        String reasonText = String.join(", ", reasons);

        String body = """
                Hello %s,
                
                We detected a blocked login attempt to your account.
                
                Details:
                - IP Address: %s
                - Device: %s
                - Reasons: %s
                
                If this was not you, please reset your password immediately.
                
                Regards,
                Security Team
                """.formatted(
                user.getFullName(),
                ip,
                userAgent,
                reasonText
        );
        sendEmail(user.getEmail(), subject, body);
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
    public void fallbackVerificationEmail(String email, String token, Throwable ex) {
        log.error("EmailService FALLBACK: verification email failed email={} reason={}", email, ex.getMessage(), ex);
    }

    public void fallbackPasswordEmail(String email, String token, Throwable ex) {
        log.error("EmailService FALLBACK: password email failed email={} reason={}",
                email, ex.getMessage(), ex);
    }

    public void fallbackOtpEmail(String email, String otp, Throwable ex) {
        log.error("EmailService FALLBACK: OTP email failed email={} reason={}",
                email, ex.getMessage(), ex);
    }

    public void fallbackHighRiskAlert(User user, String ip, String userAgent, List<String> reasons, Throwable ex) {
        log.error("SuspiciousLoginAlertService: Failed to send alert email={} reason={}", user.getEmail(), ex.getMessage());
    }
}



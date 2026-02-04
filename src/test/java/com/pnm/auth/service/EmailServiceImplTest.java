package com.pnm.auth.service;


import com.pnm.auth.domain.entity.User;
import com.pnm.auth.service.impl.email.EmailServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class EmailServiceImplTest {

    @Mock
    private JavaMailSender mailSender;

    private EmailServiceImpl emailService;

    @BeforeEach
    void setUp() {
        emailService = new EmailServiceImpl(mailSender);
        ReflectionTestUtils.setField(emailService, "baseUrl", "https://example.com");
    }

    @Test
    @DisplayName("sendVerificationEmail should send verification link email")
    void sendVerificationEmail_sendsVerificationLink() {
        emailService.sendVerificationEmail("user@example.com", "token123");

        SimpleMailMessage message = captureMessage();
        assertThat(message.getTo()).containsExactly("user@example.com");
        assertThat(message.getSubject()).isEqualTo("Verify Your Email");
        assertThat(message.getText()).contains("https://example.com/api/auth/verify?token=token123");
        assertThat(message.getFrom()).isEqualTo("noreply@project1.com");
    }

    @Test
    @DisplayName("sendSetPasswordEmail should send set-password email")
    void sendSetPasswordEmail_sendsSetPasswordLink() {
        emailService.sendSetPasswordEmail("reset@example.com", "reset-token");

        SimpleMailMessage message = captureMessage();
        assertThat(message.getTo()).containsExactly("reset@example.com");
        assertThat(message.getSubject()).isEqualTo("Set your password");
        assertThat(message.getText()).contains("https://example.com/reset-password?token=reset-token");
        assertThat(message.getText()).contains("This link expires in 15 minutes.");
        assertThat(message.getFrom()).isEqualTo("noreply@project1.com");
    }

    @Test
    @DisplayName("sendMfaOtpEmail should send OTP email")
    void sendMfaOtpEmail_sendsOtp() {
        emailService.sendMfaOtpEmail("mfa@example.com", "456789");

        SimpleMailMessage message = captureMessage();
        assertThat(message.getTo()).containsExactly("mfa@example.com");
        assertThat(message.getSubject()).isEqualTo("Your MFA Verification Code");
        assertThat(message.getText()).contains("Your OTP is: 456789");
        assertThat(message.getText()).contains("valid for 5 minutes");
        assertThat(message.getFrom()).isEqualTo("noreply@project1.com");
    }

    @Test
    @DisplayName("sendHighRiskAlert should send details about the suspicious login attempt")
    void sendHighRiskAlert_sendsAlertDetails() {
        User user = new User();
        user.setFullName("Jane Doe");
        user.setEmail("jane.doe@example.com");

        emailService.sendHighRiskAlert(
                user,
                "203.0.113.10",
                "Chrome on Linux",
                List.of("New device", "Unrecognized location")
        );

        SimpleMailMessage message = captureMessage();
        assertThat(message.getTo()).containsExactly("jane.doe@example.com");
        assertThat(message.getSubject()).isEqualTo("⚠ Suspicious Login Attempt Blocked");
        assertThat(message.getText()).contains("Hello Jane Doe");
        assertThat(message.getText()).contains("203.0.113.10");
        assertThat(message.getText()).contains("Chrome on Linux");
        assertThat(message.getText()).contains("New device, Unrecognized location");
        assertThat(message.getFrom()).isEqualTo("noreply@project1.com");
    }

    private SimpleMailMessage captureMessage() {
        ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());
        return messageCaptor.getValue();
    }
}

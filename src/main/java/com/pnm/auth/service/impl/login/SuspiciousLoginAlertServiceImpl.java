package com.pnm.auth.service.impl.login;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.service.email.EmailService;
import com.pnm.auth.service.login.SuspiciousLoginAlertService;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.retry.annotation.Retry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class SuspiciousLoginAlertServiceImpl implements SuspiciousLoginAlertService {

    private final EmailService emailService;

    @Override
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

        // ✅ DIRECT CALL: Fire and forget.
        // Since EmailService.sendEmail is @Async, this does not block the thread.
        // It runs regardless of whether the Login transaction commits or rolls back.
        emailService.sendEmail(user.getEmail(), subject, body);
    }

    // ==========================================================
    // FALLBACK METHOD
    // ==========================================================
    public void fallbackHighRiskAlert(User user, String ip, String userAgent, List<String> reasons, Throwable ex) {
        log.error("SuspiciousLoginAlertService: Failed to send alert email={} reason={}", user.getEmail(), ex.getMessage());
        // Swallow exception so we don't crash the already-failing request logic
    }
}


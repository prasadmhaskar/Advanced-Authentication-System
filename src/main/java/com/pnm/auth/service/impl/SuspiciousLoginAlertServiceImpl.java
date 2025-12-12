package com.pnm.auth.service.impl;

import com.pnm.auth.entity.User;
import com.pnm.auth.service.EmailService;
import com.pnm.auth.service.SuspiciousLoginAlertService;
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

        emailService.sendEmail(user.getEmail(), subject, body);
    }

    // ==========================================================
    // FALLBACK METHOD (MUST MATCH PARAMETERS + Throwable)
    // ==========================================================
    public void fallbackHighRiskAlert(User user, String ip, String userAgent, List<String> reasons, Throwable ex) {

        log.error(
                "Fallback triggered for SuspiciousLoginAlertService: email={} reason={}",
                user.getEmail(),
                ex.getMessage()
        );

        // Do NOT throw. Alerts should never block login flow.
        // Optional: save alert failure in logs or audit system.
    }
}


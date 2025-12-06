package com.pnm.auth.service.impl;

import com.pnm.auth.entity.User;
import com.pnm.auth.service.EmailService;
import com.pnm.auth.service.SuspiciousLoginAlertService;
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
}


package com.pnm.auth.security.maintenance;

import com.pnm.auth.repository.VerificationTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Component
@RequiredArgsConstructor
@Slf4j
public class VerificationTokenCleanupJob {

    private final VerificationTokenRepository tokenRepository;

    // runs once daily at 3 AM
    @Scheduled(cron = "0 0 3 * * ?")
    @Transactional
    public void cleanupVerificationTokens() {

        LocalDateTime cutoff = LocalDateTime.now().minusDays(7);

        int usedDeleted =
                tokenRepository.deleteUsedTokensBefore(cutoff);

        int expiredDeleted =
                tokenRepository.deleteExpiredUnusedTokensBefore(cutoff);

        if (usedDeleted > 0 || expiredDeleted > 0) {
            log.info(
                    "VerificationTokenCleanupJob: deleted usedTokens={} expiredUnusedTokens={}",
                    usedDeleted, expiredDeleted
            );
        }
    }
}


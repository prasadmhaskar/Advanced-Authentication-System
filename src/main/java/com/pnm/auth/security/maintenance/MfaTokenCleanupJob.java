package com.pnm.auth.security.maintenance;

import com.pnm.auth.repository.MfaTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Component
@RequiredArgsConstructor
@Slf4j
public class MfaTokenCleanupJob {

    private final MfaTokenRepository mfaTokenRepository;

    // Run once daily at 3 AM
    @Scheduled(cron = "0 0 3 * * ?")
    @Transactional
    public void cleanupMfaTokens() {

        // Keep last 24 hours for audit/debug
        LocalDateTime cutoff = LocalDateTime.now().minusDays(1);

        int usedDeleted =
                mfaTokenRepository.deleteUsedTokensBefore(cutoff);

        int expiredDeleted =
                mfaTokenRepository.deleteExpiredUnusedTokensBefore(cutoff);

        if (usedDeleted > 0 || expiredDeleted > 0) {
            log.info(
                    "MfaTokenCleanupJob: deleted usedTokens={} expiredUnusedTokens={}",
                    usedDeleted,
                    expiredDeleted
            );
        }
    }
}


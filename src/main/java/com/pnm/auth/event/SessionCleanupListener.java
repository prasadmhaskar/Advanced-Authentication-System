package com.pnm.auth.event;

import com.pnm.auth.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Component
@RequiredArgsConstructor
@Slf4j
public class SessionCleanupListener {

    private final RefreshTokenRepository refreshTokenRepository;

    // Define a simple DTO for the event inside or separately
    public record SessionCleanupEvent(Long userId, int limit) {}

    @Async("taskExecutor") // Ensure you have an executor named 'taskExecutor' or similar in AsyncConfig
    @EventListener
    @Transactional(propagation = Propagation.REQUIRES_NEW) // New transaction for cleanup
    public void handleSessionCleanup(SessionCleanupEvent event) {
        try {
            log.debug("Async Cleanup: Removing old sessions for user={}", event.userId());
            refreshTokenRepository.deleteOldestSessions(event.userId(), event.limit());
        } catch (Exception e) {
            // Log but don't fail the user request
            log.warn("Async Cleanup failed for user={}: {}", event.userId(), e.getMessage());
        }
    }
}
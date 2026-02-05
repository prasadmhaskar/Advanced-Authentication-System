package com.pnm.auth.event;

import com.pnm.auth.event.SessionCleanupListener.SessionCleanupEvent;
import com.pnm.auth.repository.RefreshTokenRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SessionCleanupListenerTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @InjectMocks
    private SessionCleanupListener sessionCleanupListener;

    @Test
    @DisplayName("Should invoke repository delete when event is received")
    void shouldDeleteOldestSessions() {
        // Given
        Long userId = 100L;
        int limit = 5;
        SessionCleanupEvent event = new SessionCleanupEvent(userId, limit);

        // When
        sessionCleanupListener.handleSessionCleanup(event);

        // Then
        verify(refreshTokenRepository, times(1)).deleteOldestSessions(userId, limit);
    }

    @Test
    @DisplayName("Should log error but not crash if repository fails")
    void shouldHandleRepositoryException() {
        // Given
        doThrow(new RuntimeException("DB Connection Fail"))
                .when(refreshTokenRepository).deleteOldestSessions(anyLong(), anyInt());

        SessionCleanupEvent event = new SessionCleanupEvent(1L, 5);

        // When
        sessionCleanupListener.handleSessionCleanup(event);

        // Then
        // Verify it was called, but no exception was thrown out of the listener (swallowed/logged)
        verify(refreshTokenRepository).deleteOldestSessions(1L, 5);
    }
}
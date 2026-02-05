package com.pnm.auth.orchestrator;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pnm.auth.domain.entity.RefreshToken;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.orchestrator.auth.impl.RefreshTokenOrchestratorImpl;
import com.pnm.auth.repository.RefreshTokenRepository;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.service.impl.cache.CacheManagementService;
import com.pnm.auth.service.interfaces.audit.AuditService;
import com.pnm.auth.service.interfaces.auth.TokenService;
import com.pnm.auth.web.context.RequestContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.concurrent.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RefreshTokenConcurrencyTest {

    @Mock RefreshTokenRepository refreshTokenRepository;
    @Mock TokenService tokenService;
    @Mock AuditService auditService;
    @Mock UserRepository userRepository;
    @Mock ApplicationEventPublisher eventPublisher;
    @Mock CacheManagementService cacheManagementService;
    @Mock StringRedisTemplate redisTemplate;
    @Mock ValueOperations<String, String> valueOperations;
    @Mock ObjectMapper objectMapper;

    @InjectMocks
    RefreshTokenOrchestratorImpl orchestrator;

    private User user;
    private RefreshToken validToken;
    private final String RAW_TOKEN = "race-condition-token";

    // Use a real User-Agent that resolves to "Chrome_Windows_DESKTOP"
    private final String CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36";
    private final String EXPECTED_SIG = "Chrome_Windows_DESKTOP";

    @BeforeEach
    void setup() {
        user = new User();
        user.setId(1L);
        user.setEmail("test@race.com");

        validToken = new RefreshToken();
        validToken.setToken(RAW_TOKEN);
        validToken.setUser(user);
        validToken.setExpiresAt(LocalDateTime.now().plusDays(1));
        validToken.setInvalidated(false);
        // Ensure the token expects the signature derived from the CHROME_UA
        validToken.setDeviceSignature(EXPECTED_SIG);

        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    }

    @Test
    @DisplayName("Race Condition: Loser thread waits for Winner thread and succeeds")
    void testRaceCondition_LoserWaitsAndSucceeds() throws Exception {
        // --- SCENARIO SETUP ---
        // Pass the Real User Agent here. No need to mock static parser.
        RequestContext ctx = new RequestContext("1.2.3.4", CHROME_UA, "/api/refresh");

        // Mock Repository: Always return the token object
        when(refreshTokenRepository.findByToken(RAW_TOKEN)).thenReturn(Optional.of(validToken));

        // CRITICAL: Mock MarkAsUsed
        // First call (Winner Thread) returns 1.
        // Second call (Loser Thread) returns 0.
        when(refreshTokenRepository.markAsUsed(RAW_TOKEN))
                .thenReturn(1) // T1 wins
                .thenReturn(0); // T2 loses

        // MOCK T1 SUCCESS (Winner)
        AuthenticationResult freshTokens = AuthenticationResult.builder().accessToken("new-access").build();
        when(tokenService.generateTokens(any(), any())).thenReturn(freshTokens);

        // MOCK REDIS (The Handoff)
        // T2 checks Redis inside handlePotentialReuse.
        // Call 1 (0ms): returns null (Winner hasn't finished).
        // Call 2 (150ms): returns null (Winner still working).
        // Call 3 (300ms): returns JSON (Winner finished!).
        when(valueOperations.get("refresh_grace:" + RAW_TOKEN))
                .thenReturn(null)
                .thenReturn(null)
                .thenReturn("{\"accessToken\":\"new-access\"}");

        when(objectMapper.readValue(anyString(), eq(AuthenticationResult.class))).thenReturn(freshTokens);

        // --- EXECUTION ---
        ExecutorService executor = Executors.newFixedThreadPool(2);

        // Thread 1 (Winner) Task
        Callable<AuthenticationResult> winnerTask = () -> orchestrator.refresh(RAW_TOKEN, ctx);

        // Thread 2 (Loser) Task
        Callable<AuthenticationResult> loserTask = () -> orchestrator.refresh(RAW_TOKEN, ctx);

        // Submit tasks
        Future<AuthenticationResult> f1 = executor.submit(winnerTask);

        // Small sleep ensures T1 enters the synchronized/DB block first in the mock sequence
        Thread.sleep(50);
        Future<AuthenticationResult> f2 = executor.submit(loserTask);

        AuthenticationResult r1 = f1.get(2, TimeUnit.SECONDS);
        AuthenticationResult r2 = f2.get(2, TimeUnit.SECONDS);

        // --- ASSERTIONS ---
        assertNotNull(r1, "Winner should get tokens");
        assertNotNull(r2, "Loser should get cached tokens (Requires Retry Logic!)");

        assertEquals("new-access", r1.getAccessToken());
        assertEquals("new-access", r2.getAccessToken());

        // Verify T1 did the generation
        verify(tokenService, times(1)).generateTokens(any(), any());

        // Verify T2 did NOT trigger lockout
        verify(refreshTokenRepository, never()).invalidateAllForUser(any());

        executor.shutdown();
    }
}
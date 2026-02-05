package com.pnm.auth.security.filter;

import com.pnm.auth.service.impl.redis.RedisRateLimiterServiceImpl;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RedisRRateLimiterServiceImplTest {

    @Mock
    private StringRedisTemplate redisTemplate;

    @InjectMocks
    private RedisRateLimiterServiceImpl rateLimiterService;

    @Test
    @DisplayName("Should allow request when Lua script returns count <= max")
    void shouldAllowRequest_WhenUnderLimit() {
        // Given
        String key = "test-ip";
        int max = 5;
        int window = 60;

        // Mock execute to return 1 (First request)
        when(redisTemplate.execute(any(RedisScript.class), anyList(), any()))
                .thenReturn(1L);

        // When
        boolean allowed = rateLimiterService.isAllowed(key, max, window);

        // Then
        assertTrue(allowed);

        // Verify Lua script was called with correct args
        verify(redisTemplate).execute(
                any(RedisScript.class),
                eq(Collections.singletonList(key)), // Keys
                eq(String.valueOf(window))          // Args
        );
    }

    @Test
    @DisplayName("Should block request when Lua script returns count > max")
    void shouldBlockRequest_WhenOverLimit() {
        // Given
        String key = "test-ip";
        int max = 5;

        // Mock execute to return 6 (Over limit)
        when(redisTemplate.execute(any(RedisScript.class), anyList(), any()))
                .thenReturn(6L);

        // When
        boolean allowed = rateLimiterService.isAllowed(key, max, 60);

        // Then
        assertFalse(allowed);
    }

    @Test
    @DisplayName("Should fail OPEN (allow) if Redis throws exception")
    void shouldFailOpen_WhenRedisDown() {
        // Given
        when(redisTemplate.execute(any(RedisScript.class), anyList(), any()))
                .thenThrow(new RuntimeException("Redis connection failed"));

        // When
        boolean allowed = rateLimiterService.isAllowed("key", 5, 60);

        // Then
        assertTrue(allowed, "Should default to true (allowed) if Redis fails");
    }
}
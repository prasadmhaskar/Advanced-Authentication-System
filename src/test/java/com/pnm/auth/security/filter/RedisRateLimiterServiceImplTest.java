package com.pnm.auth.security.filter;

import com.pnm.auth.service.impl.redis.RedisRateLimiterServiceImpl;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RedisRateLimiterServiceImplTest {

    @Mock
    private StringRedisTemplate redisTemplate;

    @InjectMocks
    private RedisRateLimiterServiceImpl service;

    @Test
    void isAllowedReturnsTrueWhenUnderLimit() {
        String key = "rate:ip:1";
        // FIXED: Added matchers for varargs
        when(redisTemplate.execute(any(RedisScript.class), anyList(), any(Object.class)))
                .thenReturn(1L);

        boolean allowed = service.isAllowed(key, 5, 60);

        assertTrue(allowed);
        verify(redisTemplate).execute(
                any(RedisScript.class),
                eq(Collections.singletonList(key)),
                eq("60")
        );
    }

    @Test
    void isAllowedReturnsFalseWhenLimitExceeded() {
        String key = "rate:ip:2";
        // FIXED: Added matchers for varargs
        when(redisTemplate.execute(any(RedisScript.class), anyList(), any(Object.class)))
                .thenReturn(6L);

        boolean allowed = service.isAllowed(key, 5, 60);

        assertFalse(allowed);
    }

    @Test
    void isAllowedReturnsTrueWhenRedisThrows() {
        String key = "rate:ip:3";
        // FIXED: Added matchers for varargs so the stub actually throws
        when(redisTemplate.execute(any(RedisScript.class), anyList(), any(Object.class)))
                .thenThrow(new RuntimeException("Redis connection failed"));

        boolean allowed = service.isAllowed(key, 5, 60);

        // Should fail OPEN (allow request)
        assertTrue(allowed);
    }

    @Test
    void refundDeletesRateLimitKey() {
        service.refund("user-1");
        verify(redisTemplate).delete("rate_limit:user-1");
    }
}
package com.pnm.auth.security.filter;

import com.pnm.auth.service.impl.redis.RedisRateLimiterServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RedisRateLimiterServiceImplTest {

    @Mock
    private StringRedisTemplate redisTemplate;

    @Mock
    private ValueOperations<String, String> valueOperations;

    private RedisRateLimiterServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new RedisRateLimiterServiceImpl(redisTemplate);
    }

    @Test
    void isAllowedSetsExpiryOnFirstRequest() {
        String key = "rate:ip:1";
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.increment(key)).thenReturn(1L);

        boolean allowed = service.isAllowed(key, 5, 60);

        assertTrue(allowed);
        verify(redisTemplate).expire(key, 60, TimeUnit.SECONDS);
    }

    @Test
    void isAllowedRejectsWhenLimitExceeded() {
        String key = "rate:ip:2";
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.increment(key)).thenReturn(6L);

        boolean allowed = service.isAllowed(key, 5, 60);

        assertFalse(allowed);
        verify(redisTemplate, never()).expire(key, 60, TimeUnit.SECONDS);
    }

    @Test
    void isAllowedReturnsFalseWhenIncrementNull() {
        String key = "rate:ip:3";
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.increment(key)).thenReturn(null);

        boolean allowed = service.isAllowed(key, 5, 60);

        assertFalse(allowed);
        verify(redisTemplate, never()).expire(key, 60, TimeUnit.SECONDS);
    }

    @Test
    void isAllowedReturnsTrueWhenRedisThrows() {
        String key = "rate:ip:4";
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.increment(key)).thenThrow(new RuntimeException("Redis down"));

        boolean allowed = service.isAllowed(key, 5, 60);

        assertTrue(allowed);
    }

    @Test
    void refundDeletesRateLimitKey() {
        service.refund("user-1");

        verify(redisTemplate).delete("rate_limit:user-1");
    }
}


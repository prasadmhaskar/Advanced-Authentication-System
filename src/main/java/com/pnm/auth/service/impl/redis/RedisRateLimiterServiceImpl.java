package com.pnm.auth.service.impl.redis;

import com.pnm.auth.service.interfaces.redis.RedisRateLimiterService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class RedisRateLimiterServiceImpl implements RedisRateLimiterService {

    private final StringRedisTemplate redisTemplate;

    @Override
    public boolean isAllowed(String key, int maxRequests, int windowSeconds) {
        try {
            // Increment counter
            Long currentCount = redisTemplate.opsForValue().increment(key);

            // Set expiry if this is the first request
            if (currentCount != null && currentCount == 1) {
                redisTemplate.expire(key, windowSeconds, TimeUnit.SECONDS);
            }

            // Check limit
            return currentCount != null && currentCount <= maxRequests;

        } catch (Exception e) {
            // If Redis is down, we allow traffic rather than crashing the whole app.
            log.error("Rate Limiter Failed (Redis Down?): {}", e.getMessage());
            return true;
        }
    }

    @Override
    public void refund(String key) {
        redisTemplate.delete("rate_limit:" + key);
    }

}

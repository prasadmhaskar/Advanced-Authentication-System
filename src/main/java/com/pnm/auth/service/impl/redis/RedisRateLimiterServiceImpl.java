package com.pnm.auth.service.impl.redis;

import com.pnm.auth.service.redis.RedisRateLimiterService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
@RequiredArgsConstructor
@Slf4j
public class RedisRateLimiterServiceImpl implements RedisRateLimiterService {

    private final StringRedisTemplate redisTemplate;

    /**
     * @param key - the unique key (IP or IP+path)
     * @param limit - max allowed requests
     * @param windowSeconds - time window
     * @return true = allowed, false = blocked
     */
    @Override
    public boolean isAllowed(String key, int limit, int windowSeconds) {

        String redisKey = "rate_limit:" + key;

        Long count = redisTemplate.opsForValue().increment(redisKey);

        if (count != null && count == 1) {
            // First request → set expiration window
            redisTemplate.expire(redisKey, Duration.ofSeconds(windowSeconds));
        }

        return count != null && count <= limit;
    }
}

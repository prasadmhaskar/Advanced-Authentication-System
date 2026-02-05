package com.pnm.auth.service.impl.redis;

import com.pnm.auth.service.interfaces.redis.RedisRateLimiterService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class RedisRateLimiterServiceImpl implements RedisRateLimiterService {

    private final StringRedisTemplate redisTemplate;

    // KEYS[1] = Rate Limit Key
    // ARGV[1] = Window in Seconds
    private static final String LUA_SCRIPT_RateLimit = """
            local current = redis.call('INCR', KEYS[1])
            if current == 1 then
                redis.call('EXPIRE', KEYS[1], ARGV[1])
            end
            return current
            """;

    private final RedisScript<Long> rateLimitScript = new DefaultRedisScript<>(LUA_SCRIPT_RateLimit, Long.class);

    @Override
    public boolean isAllowed(String key, int maxRequests, int windowSeconds) {
        try {
            // --- FIX START: Atomic Execution ---
            Long currentCount = redisTemplate.execute(
                    rateLimitScript,
                    Collections.singletonList(key), // KEYS
                    String.valueOf(windowSeconds)   // ARGV
            );
            // --- FIX END ---

            return currentCount != null && currentCount <= maxRequests;

        } catch (Exception e) {
            log.error("Rate Limiter Failed (Redis Down?): {}", e.getMessage());
            return true; // Fail open
        }
    }

    @Override
    public void refund(String key) {
        redisTemplate.delete("rate_limit:" + key);
    }

}

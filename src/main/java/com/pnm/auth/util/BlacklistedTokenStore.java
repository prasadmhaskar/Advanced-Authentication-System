package com.pnm.auth.util;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Slf4j
@Component
@RequiredArgsConstructor
public class BlacklistedTokenStore {

    private final StringRedisTemplate redisTemplate;
    private static final String BLACKLIST_PREFIX = "jwt:blacklist:";

    public void blacklistToken(String token, long expiryTimeMillis) {
        long now = System.currentTimeMillis();
        long durationMillis = expiryTimeMillis - now;

        if (durationMillis > 0) {
            // Store in Redis with an automatic TTL (Time To Live)
            // We don't need a value, so we just store "true"
            redisTemplate.opsForValue().set(
                    BLACKLIST_PREFIX + token,
                    "true",
                    durationMillis,
                    TimeUnit.MILLISECONDS
            );
            log.info("Token blacklisted in Redis. TTL: {}ms. Prefix: {}",
                    durationMillis, token.substring(0, Math.min(token.length(), 10)));
        }
    }

    public boolean isBlacklisted(String token) {
        // Simple O(1) lookup
        return redisTemplate.hasKey(BLACKLIST_PREFIX + token);
    }
}

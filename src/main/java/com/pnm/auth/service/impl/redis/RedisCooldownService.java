package com.pnm.auth.service.impl.redis;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class RedisCooldownService {

    private final StringRedisTemplate redisTemplate;

    public boolean isInCooldown(String key) {
        return redisTemplate.hasKey(key);
    }

    public void startCooldown(String key, Duration duration) {
        redisTemplate.opsForValue().set(
                key,
                "1",
                duration
        );
    }

    public long getRemainingSeconds(String key) {
        Long ttl = redisTemplate.getExpire(key, TimeUnit.SECONDS);
        return ttl > 0 ? ttl : 0;
    }
}


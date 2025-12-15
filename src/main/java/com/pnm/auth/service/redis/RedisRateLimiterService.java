package com.pnm.auth.service.redis;

public interface RedisRateLimiterService {

    boolean isAllowed(String key, int limit, int windowSeconds);
}

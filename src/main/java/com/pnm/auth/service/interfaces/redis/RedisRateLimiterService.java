package com.pnm.auth.service.interfaces.redis;

public interface RedisRateLimiterService {

    boolean isAllowed(String key, int limit, int windowSeconds);
    void refund(String key);
}

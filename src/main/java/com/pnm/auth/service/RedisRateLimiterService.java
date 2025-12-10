package com.pnm.auth.service;

public interface RedisRateLimiterService {

    public boolean isAllowed(String key, int limit, int windowSeconds);
}

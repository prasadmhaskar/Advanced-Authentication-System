package com.pnm.auth.util;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Component
public class BlacklistedTokenStore {

    private final Map<String, Long> blacklist = new ConcurrentHashMap<>();

    public void blacklistToken(String token, long expiryTimeMillis) {
        blacklist.put(token, expiryTimeMillis);
        log.info("BlacklistedTokenStore: Token blacklisted tokenPrefix={}", token.substring(0, 10));
    }

    public boolean isBlacklisted(String token) {
        Long expiry = blacklist.get(token);
        if (expiry == null) return false;

        if (expiry < System.currentTimeMillis()) {
            blacklist.remove(token);
            return false;
        }

        return true;
    }
}

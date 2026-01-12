package com.pnm.auth.service.impl.cache;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class CacheManagementService {

    @CacheEvict(value = "user_details", key = "#email")
    public void evictUserFromCache(String email) {
        log.info("Cache cleared for {}", email);
    }
}

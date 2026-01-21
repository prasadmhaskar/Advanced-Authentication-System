package com.pnm.auth.infrastructure; // Matches the directory structure

import com.pnm.auth.AbstractIntegrationTest;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.service.impl.user.UserDetailsImpl;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RedisSerializationTest extends AbstractIntegrationTest {

    @Autowired
    private CacheManager cacheManager;

    @Test
    @DisplayName("CRITICAL: Verify UserDetailsImpl serializes/deserializes correctly in Redis")
    void testUserDetailsSerialization() {
        // 1. Setup Data
        User mockUser = new User();
        mockUser.setId(100L);
        mockUser.setEmail("test@serialization.com");
        mockUser.setPassword("hashed_pass");
        mockUser.setActive(true);
        mockUser.setTokenVersion(5);
        mockUser.setRoles(List.of("ROLE_USER", "ROLE_ADMIN"));

        // Create the object that caused the crash (UserDetailsImpl)
        UserDetailsImpl userDetails = new UserDetailsImpl(mockUser);

        // 2. Get Cache
        Cache cache = cacheManager.getCache("user_details");
        assertNotNull(cache, "Cache 'user_details' should exist");

        // 3. Write to Redis (This tests Serialization)
        assertDoesNotThrow(() -> cache.put(mockUser.getEmail(), userDetails),
                "Serialization failed! Check CacheConfig ObjectMapper settings.");

        // 4. Read from Redis (This tests Deserialization)
        UserDetailsImpl cachedUser = cache.get(mockUser.getEmail(), UserDetailsImpl.class);

        // 5. Assertions
        assertNotNull(cachedUser, "Should retrieve object from cache");
        assertEquals(mockUser.getEmail(), cachedUser.getUsername());
        assertEquals(2, cachedUser.getAuthorities().size());

        // Verify SimpleGrantedAuthority survived the trip
        assertTrue(cachedUser.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_ADMIN")));

        System.out.println("✅ Redis Serialization Test Passed");
    }
}
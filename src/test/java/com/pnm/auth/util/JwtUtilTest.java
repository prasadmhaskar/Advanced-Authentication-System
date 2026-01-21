package com.pnm.auth.util;

import com.pnm.auth.AbstractIntegrationTest;
import com.pnm.auth.domain.entity.User;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

class JwtUtilTest extends AbstractIntegrationTest {

    @Autowired
    private JwtUtil jwtUtil;

    @Test
    @DisplayName("CRITICAL: Verify JwtUtil generates non-null tokens")
    void generateToken_Success() {
        // 1. Setup Mock User
        User user = new User();
        user.setId(1L);
        user.setEmail("test@jwt.com");
        user.setRoles(Collections.singletonList("ROLE_USER"));
        user.setTokenVersion(1);

        // 2. Generate Token
        String token = jwtUtil.generateAccessToken(user);

        // 3. Assert
        System.out.println("Generated Test Token: " + token);
        assertNotNull(token, "JwtUtil returned NULL token! Check properties injection.");
        assertFalse(token.isEmpty(), "JwtUtil returned empty token!");

        // 4. Validate
        assertTrue(!jwtUtil.isTokenExpired(token), "Generated token should be valid");
    }
}
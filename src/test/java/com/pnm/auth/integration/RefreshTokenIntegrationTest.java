package com.pnm.auth.integration;

import com.pnm.auth.AbstractIntegrationTest;
import com.pnm.auth.domain.entity.RefreshToken;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.dto.request.LoginRequest;
import com.pnm.auth.dto.request.RefreshTokenRequest;
import com.pnm.auth.repository.TrustedDeviceRepository;
import com.pnm.auth.util.JwtUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class RefreshTokenIntegrationTest extends AbstractIntegrationTest {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private TrustedDeviceRepository trustedDeviceRepository;

//    @Autowired
//    private TrustedDeviceRepository trustedDeviceRepository;

    @Test
    @DisplayName("Should rotate refresh token successfully")
    void shouldRotateRefreshTokenSuccessfully() throws Exception {
        // 1. REGISTER
        User user = new User();
        user.setEmail("rotate@test.com");
        user.setFullName("Rotate User");
        user.setPassword(passwordEncoder.encode("Password123!"));
        user.setEmailVerified(true);
        user.setMfaEnabled(false);
        user = userRepository.save(user);
        final Long userId = user.getId();

        // 2. FORCE TRUST (Bypass Risk Engine)
        // A. Add IP Log to avoid "NEW_IP_FOR_USER" risk
        com.pnm.auth.domain.entity.UserIpLog ipLog = new com.pnm.auth.domain.entity.UserIpLog();
        ipLog.setUserId(user.getId());
        ipLog.setIpAddress("127.0.0.1"); // Match MockMvc
        ipLog.setLoginTime(java.time.LocalDateTime.now().minusDays(1)); // Logged in yesterday
        ipLog.setDeviceSignature("UNKNOWN"); // Match system default for null UA
        ipLog.setIsSuspicious(false);
        userIpLogRepository.save(ipLog);

        // B. Trust the Device to avoid "UNTRUSTED_DEVICE" risk
        com.pnm.auth.domain.entity.TrustedDevice trustedDevice = new com.pnm.auth.domain.entity.TrustedDevice();
        trustedDevice.setUserId(user.getId());
        trustedDevice.setDeviceSignature("UNKNOWN"); // Match default
        trustedDevice.setDeviceName("Test Device");
        trustedDevice.setTrustedAt(java.time.LocalDateTime.now());
        trustedDevice.setActive(true);
        trustedDeviceRepository.save(trustedDevice);

        // 3. LOGIN (Should now be RISK-FREE)
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("rotate@test.com");
        loginRequest.setPassword("Password123!");

        String loginResponse = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.outcome").value("SUCCESS")) // Ensure we actually logged in!
                .andReturn().getResponse().getContentAsString();

        // Extract Refresh Token
        String refreshTokenString = com.jayway.jsonpath.JsonPath.read(loginResponse, "$.data.refreshToken");
        assertThat(refreshTokenString).isNotNull();

        // 4. REFRESH
        RefreshTokenRequest refreshRequest = new RefreshTokenRequest();
        refreshRequest.setRefreshToken(refreshTokenString);

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.data.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.data.refreshToken").value(org.hamcrest.Matchers.not(refreshTokenString)));

        // 5. ASSERTIONS
        // Check old token is handled (Used or Deleted)
        RefreshToken oldTokenState = refreshTokenRepository.findByToken(refreshTokenString).orElse(null);
        if (oldTokenState != null) {
            assertThat(oldTokenState.isUsed()).as("Old token should be marked used").isTrue();
        }

        // Check new token exists
        long count = refreshTokenRepository.findAll().stream()
                .filter(t -> t.getUser().getId().equals(userId) && !t.getToken().equals(refreshTokenString))
                .count();
        assertThat(count).as("A new refresh token should be present in DB").isEqualTo(1);
    }

    @Test
    @DisplayName("Should Reject Used Refresh Token (Replay Attack)")
    void shouldRejectUsedRefreshToken() throws Exception {
        // 1. SETUP
        User user = new User();
        user.setEmail("replay@test.com");
        user.setFullName("Replay User");
        user.setPassword(passwordEncoder.encode("Pass!"));
        user.setEmailVerified(true);
        userRepository.save(user);

        String tokenString = jwtUtil.generateRefreshToken(user);

        RefreshToken usedToken = new RefreshToken();
        usedToken.setUser(user);
        usedToken.setToken(tokenString);
        usedToken.setExpiresAt(LocalDateTime.now().plusSeconds(3600));
        usedToken.setCreatedAt(LocalDateTime.now());
        usedToken.setUsed(true); // <--- ALREADY USED
        usedToken.setInvalidated(false);
        usedToken.setDeviceSignature("unknown");
        refreshTokenRepository.save(usedToken);

        // 2. EXECUTE
        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setRefreshToken(tokenString);

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized()) // Expect 401 or 403
                .andExpect(jsonPath("$.success").value(false));
    }
}
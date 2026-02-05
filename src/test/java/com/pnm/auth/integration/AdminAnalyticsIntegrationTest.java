package com.pnm.auth.integration;

import com.pnm.auth.AbstractIntegrationTest;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.entity.UserActivity;
import com.pnm.auth.dto.request.LoginRequest;
import com.pnm.auth.repository.TrustedDeviceRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class AdminAnalyticsIntegrationTest extends AbstractIntegrationTest {

    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private TrustedDeviceRepository trustedDeviceRepository;

    @Test
    @DisplayName("Should return correct analytics data for admin")
    void shouldReturnCorrectAnalytics() throws Exception {
        // ==========================================
        // 1. SETUP: Create Admin
        // ==========================================
        User admin = new User();
        admin.setEmail("admin.stats@test.com");
        admin.setFullName("Admin Stats");
        admin.setPassword(passwordEncoder.encode("AdminPass123!"));
        admin.setEmailVerified(true);
        admin.setRoles(List.of("ROLE_ADMIN", "ROLE_USER"));
        admin.setActive(true);
        userRepository.save(admin);

        // ==========================================
        // 2. SETUP: Create Standard Users (for stats)
        // ==========================================
        createActiveUser("user1@test.com");
        createActiveUser("user2@test.com");

        // Total users = 3 (1 Admin + 2 Users)

        // ==========================================
        // 3. SETUP: Create Activity Logs
        // ==========================================
        // Simulate 2 logins for user1
        createActivity("user1@test.com", "Login successful", true);
        createActivity("user1@test.com", "Login successful", true);

        // Simulate 1 failed login for user2
        createActivity("user2@test.com", "Invalid credentials", false);

        // ==========================================
        // 4. LOGIN AS ADMIN
        // ==========================================
        // Trust seeding (Skip if your config allows admin to bypass, but safer to add)
        seedTrustForUser(admin);

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("admin.stats@test.com");
        loginRequest.setPassword("AdminPass123!");

        String loginResponse = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String adminToken = com.jayway.jsonpath.JsonPath.read(loginResponse, "$.data.accessToken");

        // ==========================================
        // 5. FETCH ANALYTICS
        // ==========================================
        // Assuming endpoint is /api/admin/analytics. Adjust if different.
        mockMvc.perform(get("/api/admin/analytics")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                // Verify specific data points based on your DTO structure
                // Adjust field names (e.g. totalUsers vs total_users) to match your DTO
                .andExpect(jsonPath("$.data.totalUsers").value(org.hamcrest.Matchers.greaterThanOrEqualTo(3)))
                .andExpect(jsonPath("$.data.activeUsers").value(org.hamcrest.Matchers.greaterThanOrEqualTo(3)))
        // If you track 'totalLogins' or 'failedLogins'
        // .andExpect(jsonPath("$.data.totalLogins").value(org.hamcrest.Matchers.greaterThanOrEqualTo(2)))
        ;
    }

    @Test
    @DisplayName("Should deny non-admin access to analytics")
    void shouldDenyNonAdminAccess() throws Exception {
        // 1. Setup User
        User user = createActiveUser("peasant@test.com");
        seedTrustForUser(user);

        // 2. Login
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("peasant@test.com");
        loginRequest.setPassword("Password123!");

        String loginResponse = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String userToken = com.jayway.jsonpath.JsonPath.read(loginResponse, "$.data.accessToken");

        // 3. Attempt Access
        mockMvc.perform(get("/api/admin/analytics")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    // --- Helpers ---

    private User createActiveUser(String email) {
        User user = new User();
        user.setEmail(email);
        user.setFullName("Test User");
        user.setPassword(passwordEncoder.encode("Password123!"));
        user.setEmailVerified(true);
        user.setRoles(List.of("ROLE_USER"));
        user.setActive(true);
        user.setMfaEnabled(false);
        return userRepository.save(user);
    }

    private void createActivity(String email, String message, boolean success) {
        // Need user ID for activity
        User user = userRepository.findByEmail(email).orElseThrow();

        UserActivity activity = new UserActivity();
        activity.setUserId(user.getId());
        activity.setEmail(email);
        activity.setIpAddress("127.0.0.1");
        activity.setUserAgent("Test-Agent");
        activity.setMessage(message);
        activity.setStatus(success ? "SUCCESS" : "FAILURE"); // Adjust status enum/string if needed
        activity.setCreatedAt(LocalDateTime.now());
        userActivityRepository.save(activity);
    }

    private void seedTrustForUser(User user) {
        com.pnm.auth.domain.entity.UserIpLog ipLog = new com.pnm.auth.domain.entity.UserIpLog();
        ipLog.setUserId(user.getId());
        ipLog.setIpAddress("127.0.0.1");
        ipLog.setLoginTime(LocalDateTime.now().minusDays(1));
        ipLog.setDeviceSignature("UNKNOWN");
        ipLog.setIsSuspicious(false);
        userIpLogRepository.save(ipLog);

        com.pnm.auth.domain.entity.TrustedDevice td = new com.pnm.auth.domain.entity.TrustedDevice();
        td.setUserId(user.getId());
        td.setDeviceSignature("UNKNOWN");
        td.setTrustedAt(LocalDateTime.now());
        td.setActive(true);
        trustedDeviceRepository.save(td);
    }
}
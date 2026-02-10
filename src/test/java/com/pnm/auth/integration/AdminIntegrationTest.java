package com.pnm.auth.integration;

import com.pnm.auth.AbstractIntegrationTest;
import com.pnm.auth.domain.entity.TrustedDevice;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.entity.UserIpLog;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch; // CHANGED FROM POST
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class AdminIntegrationTest extends AbstractIntegrationTest {

    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private TrustedDeviceRepository trustedDeviceRepository;

    @Test
    @DisplayName("Should allow admin to list and block/unblock users")
    void shouldAllowAdminActions() throws Exception {
        // Create Admin User
        User admin = new User();
        admin.setEmail("admin@test.com");
        admin.setFullName("Admin User");
        admin.setPassword(passwordEncoder.encode("AdminPass123!"));
        admin.setEmailVerified(true);
        admin.setRoles(List.of("ROLE_ADMIN", "ROLE_USER"));
        admin.setActive(true);
        admin = userRepository.save(admin);

        // Create Normal User
        User normalUser = new User();
        normalUser.setEmail("user@test.com");
        normalUser.setFullName("Normal User");
        normalUser.setPassword(passwordEncoder.encode("UserPass123!"));
        normalUser.setEmailVerified(true);
        normalUser.setRoles(List.of("ROLE_USER"));
        normalUser.setActive(true);
        normalUser = userRepository.save(normalUser);

        // LOGIN AS ADMIN (With Trust Bypass)
        UserIpLog ipLog = new UserIpLog();
        ipLog.setUserId(admin.getId());
        ipLog.setIpAddress("127.0.0.1");
        ipLog.setLoginTime(LocalDateTime.now().minusDays(1));
        ipLog.setDeviceSignature("UNKNOWN");
        ipLog.setIsSuspicious(false);
        userIpLogRepository.save(ipLog);

        TrustedDevice td = new TrustedDevice();
        td.setUserId(admin.getId());
        td.setDeviceSignature("UNKNOWN");
        td.setTrustedAt(LocalDateTime.now());
        td.setActive(true);
        trustedDeviceRepository.save(td);

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("admin@test.com");
        loginRequest.setPassword("AdminPass123!");

        String loginResponse = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String adminToken = com.jayway.jsonpath.JsonPath.read(loginResponse, "$.data.accessToken");

        // LIST USERS
        mockMvc.perform(get("/api/admin/users")
                        .header("Authorization", "Bearer " + adminToken)
                        .param("page", "0")
                        .param("size", "10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));

        // BLOCK USER
        mockMvc.perform(patch("/api/admin/users/" + normalUser.getId() + "/block") // CHANGED
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));

        // Verify DB
        User blockedUser = userRepository.findById(normalUser.getId()).orElseThrow();
        assertThat(blockedUser.isActive()).as("User should be blocked (active=false)").isFalse();

        // UNBLOCK USER
        mockMvc.perform(patch("/api/admin/users/" + normalUser.getId() + "/unblock") // CHANGED
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));

        // Verify DB
        User unblockedUser = userRepository.findById(normalUser.getId()).orElseThrow();
        assertThat(unblockedUser.isActive()).as("User should be unblocked (active=true)").isTrue();
    }

    @Test
    @DisplayName("Should deny non-admin access to admin endpoints")
    void shouldDenyNonAdmin() throws Exception {

        User user = new User();
        user.setEmail("hacker@test.com");
        user.setFullName("Hacker User");
        user.setPassword(passwordEncoder.encode("Password123!"));
        user.setRoles(List.of("ROLE_USER"));
        user.setEmailVerified(true);
        user.setMfaEnabled(false);
        user = userRepository.save(user);

        // Trust Seeding
        UserIpLog ipLog = new UserIpLog();
        ipLog.setUserId(user.getId());
        ipLog.setIpAddress("127.0.0.1");
        ipLog.setLoginTime(LocalDateTime.now().minusDays(1));
        ipLog.setDeviceSignature("UNKNOWN");
        ipLog.setIsSuspicious(false);
        userIpLogRepository.save(ipLog);

        TrustedDevice td = new TrustedDevice();
        td.setUserId(user.getId());
        td.setDeviceSignature("UNKNOWN");
        td.setTrustedAt(LocalDateTime.now());
        td.setActive(true);
        trustedDeviceRepository.save(td);

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("hacker@test.com");
        loginRequest.setPassword("Password123!");

        String response = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String userToken = com.jayway.jsonpath.JsonPath.read(response, "$.data.accessToken");

        // ATTEMPT ADMIN ACTION
        mockMvc.perform(get("/api/admin/users")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden()); // 403
    }
}
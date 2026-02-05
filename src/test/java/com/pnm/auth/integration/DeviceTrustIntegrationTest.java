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

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class DeviceTrustIntegrationTest extends AbstractIntegrationTest {

    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private TrustedDeviceRepository trustedDeviceRepository;

    @Test
    @DisplayName("Should list and remove trusted devices")
    void shouldListAndRemoveTrustedDevices() throws Exception {
        // 1. SETUP: User
        User user = new User();
        user.setEmail("device@test.com");
        user.setFullName("Device User");
        user.setPassword(passwordEncoder.encode("Password123!"));
        user.setEmailVerified(true);
        user.setMfaEnabled(false);
        user = userRepository.save(user);

        // 2. SETUP: Force Trust for Test Environment (Bypass Risk Engine)
        // A. IP Trust
        UserIpLog ipLog = new UserIpLog();
        ipLog.setUserId(user.getId());
        ipLog.setIpAddress("127.0.0.1"); // Matches MockMvc
        ipLog.setLoginTime(LocalDateTime.now().minusDays(1));
        ipLog.setDeviceSignature("UNKNOWN"); // Matches MockMvc default
        ipLog.setIsSuspicious(false);
        userIpLogRepository.save(ipLog);

        // B. Device Trust (The device we are logging in from)
        TrustedDevice currentDevice = new TrustedDevice();
        currentDevice.setUserId(user.getId());
        currentDevice.setDeviceSignature("UNKNOWN");
        currentDevice.setDeviceName("Test Runner");
        currentDevice.setTrustedAt(LocalDateTime.now());
        currentDevice.setActive(true);
        trustedDeviceRepository.save(currentDevice);

        // 3. SETUP: Add EXTRA dummy devices (The ones we want to list/delete)
        TrustedDevice device1 = new TrustedDevice();
        device1.setUserId(user.getId());
        device1.setDeviceName("Chrome on Mac");
        device1.setDeviceSignature("sig-111");
        device1.setTrustedAt(LocalDateTime.now());
        device1.setActive(true);
        trustedDeviceRepository.save(device1);

        TrustedDevice device2 = new TrustedDevice();
        device2.setUserId(user.getId());
        device2.setDeviceName("Safari on iPhone");
        device2.setDeviceSignature("sig-222");
        device2.setTrustedAt(LocalDateTime.now());
        device2.setActive(true);
        device2 = trustedDeviceRepository.save(device2); // Keep ref for delete

        // 4. LOGIN (Now should be SUCCESS)
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("device@test.com");
        loginRequest.setPassword("Password123!");

        String loginResponse = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.outcome").value("SUCCESS")) // Critical check
                .andReturn().getResponse().getContentAsString();

        String accessToken = com.jayway.jsonpath.JsonPath.read(loginResponse, "$.data.accessToken");
        assertThat(accessToken).as("Access token must not be null").isNotNull();

        // 5. LIST DEVICES
        mockMvc.perform(get("/api/auth/me/devices")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                // Should see at least 3: Current(UNKNOWN) + Device1 + Device2
                .andExpect(jsonPath("$.data.length()").value(org.hamcrest.Matchers.greaterThanOrEqualTo(3)));

        // 6. REMOVE DEVICE 2
        mockMvc.perform(delete("/api/auth/me/devices/" + device2.getId())
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));

        // 7. VERIFY REMOVAL
        // Check if it's gone OR if active=false
        boolean exists = trustedDeviceRepository.existsById(device2.getId());
        if (exists) {
            TrustedDevice deletedDevice = trustedDeviceRepository.findById(device2.getId()).orElseThrow();
            assertThat(deletedDevice.getActive()).as("Device should be deactivated").isFalse();
        } else {
            // Hard delete is also acceptable
            assertThat(exists).as("Device should be deleted").isFalse();
        }
    }
}
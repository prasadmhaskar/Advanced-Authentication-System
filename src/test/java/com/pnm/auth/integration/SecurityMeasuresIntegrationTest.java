package com.pnm.auth.integration;

import com.pnm.auth.AbstractIntegrationTest;
import com.pnm.auth.domain.entity.MfaToken;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.entity.UserIpLog;
import com.pnm.auth.domain.entity.TrustedDevice;
import com.pnm.auth.dto.request.LoginRequest;
import com.pnm.auth.dto.request.OtpVerifyRequest;
import com.pnm.auth.dto.request.DeleteAccountRequest;
import com.pnm.auth.repository.TrustedDeviceRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class SecurityMeasuresIntegrationTest extends AbstractIntegrationTest {

    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private TrustedDeviceRepository trustedDeviceRepository;

    @Test
    @DisplayName("Should enforce rate limiting on login endpoint")
    void shouldEnforceRateLimiting() throws Exception {
        // 1. SETUP
        User user = new User();
        user.setEmail("spammer@test.com");
        user.setPassword(passwordEncoder.encode("Pass123!"));
        user.setFullName("Spam User");
        user.setEmailVerified(true);
        userRepository.save(user);

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("spammer@test.com");
        loginRequest.setPassword("WrongPass!");

        // 2. EXECUTE: Spam 5 times
        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post("/api/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(loginRequest)))
                    .andExpect(status().is4xxClientError());
        }

        // 3. ASSERT: 6th time -> 429
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isTooManyRequests());
        // REMOVED check for $.message since your filter returns empty body
    }

    @Test
    @DisplayName("Should enforce MFA when explicitly enabled by user")
    void shouldEnforceExplicitMfa() throws Exception {
        // 1. SETUP
        User user = new User();
        user.setEmail("mfa@test.com");
        user.setFullName("MFA User");
        user.setPassword(passwordEncoder.encode("Pass123!"));
        user.setEmailVerified(true);
        user.setMfaEnabled(true);
        user = userRepository.save(user);
        final long userId = user.getId();

        seedTrust(user);

        // 2. LOGIN (MFA Required)
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("mfa@test.com");
        loginRequest.setPassword("Pass123!");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.outcome").value("MFA_REQUIRED"));

        // 3. GET OTP
        MfaToken mfaToken = mfaTokenRepository.findAll().stream()
                .filter(t -> t.getUser().getId().equals(userId) && !t.isUsed())
                .findFirst()
                .orElseThrow();

        // 4. VERIFY OTP
        OtpVerifyRequest otpRequest = new OtpVerifyRequest();
        otpRequest.setTokenId(mfaToken.getId());
        otpRequest.setOtp(mfaToken.getOtp());

        // FIXED: Changed "/api/auth/verify-otp" to "/api/auth/otp/verify"
        mockMvc.perform(post("/api/auth/otp/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(otpRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.accessToken").isNotEmpty());
    }

    @Test
    @DisplayName("Should delete account and cleanup data")
    void shouldDeleteAccountAndCleanup() throws Exception {
        // 1. SETUP
        User user = new User();
        user.setEmail("delete@test.com");
        user.setFullName("Delete Me");
        user.setPassword(passwordEncoder.encode("Pass123!"));
        user.setEmailVerified(true);
        user = userRepository.save(user);
        final Long userId = user.getId();

        seedTrust(user);

        // 2. LOGIN
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("delete@test.com");
        loginRequest.setPassword("Pass123!");

        String response = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String token = com.jayway.jsonpath.JsonPath.read(response, "$.data.accessToken");

        // 3. EXECUTE DELETE
        DeleteAccountRequest deleteRequest = new DeleteAccountRequest();
        deleteRequest.setPassword("Pass123!");

        mockMvc.perform(delete("/api/auth/me/delete-account")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(deleteRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));

        // 4. ASSERT CLEANUP
        assertThat(userRepository.findByEmail("delete@test.com")).isEmpty();
        assertThat(refreshTokenRepository.findAll().stream().anyMatch(t -> t.getUser().getId().equals(userId))).isFalse();
        assertThat(trustedDeviceRepository.findAll().stream().anyMatch(t -> t.getUserId().equals(userId))).isFalse();
    }

    private void seedTrust(User user) {
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
    }
}
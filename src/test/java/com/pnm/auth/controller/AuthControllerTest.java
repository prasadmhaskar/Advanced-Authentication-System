package com.pnm.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pnm.auth.AbstractIntegrationTest;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.dto.request.LoginRequest;
import com.pnm.auth.dto.request.RegisterRequest;
import com.pnm.auth.repository.*;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;

import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@AutoConfigureMockMvc
class AuthControllerTest extends AbstractIntegrationTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private PasswordEncoder passwordEncoder;

    // --- Repositories for Cleanup ---
    @Autowired private UserRepository userRepository;
    @Autowired private RefreshTokenRepository refreshTokenRepository;
    @Autowired private MfaTokenRepository mfaTokenRepository;
    @Autowired private VerificationTokenRepository verificationTokenRepository;
    @Autowired private UserIpLogRepository userIpLogRepository;
    @Autowired private UserActivityRepository userActivityRepository;
    @Autowired private TrustedDeviceRepository trustedDeviceRepository;
    @Autowired private UserOAuthProviderRepository userOAuthProviderRepository;

    @BeforeEach
    void setUp() {
        // CRITICAL: Delete children first to avoid Foreign Key Constraint Violations
        mfaTokenRepository.deleteAll();
        refreshTokenRepository.deleteAll();
        verificationTokenRepository.deleteAll();
        userIpLogRepository.deleteAll();
        userActivityRepository.deleteAll();
        trustedDeviceRepository.deleteAll();
        userOAuthProviderRepository.deleteAll();

        // Now it is safe to delete users
        userRepository.deleteAll();
    }

    @Test
    @DisplayName("Should Register New User Successfully")
    void register_Success() throws Exception {
        RegisterRequest request = new RegisterRequest();
        request.setFullName("Integration Test User");
        request.setEmail("newuser@example.com");
        request.setPassword("StrongPass123!");

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andDo(print())
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.data.user.email", is("newuser@example.com")));

        assertTrue(userRepository.findByEmail("newuser@example.com").isPresent());
    }

    @Test
    @DisplayName("Should Login and Return Access Token")
    void login_Success() throws Exception {
        // 1. Seed DB
        User user = new User();
        user.setFullName("Login User");
        user.setEmail("login@example.com");
        user.setPassword(passwordEncoder.encode("MyPassword123!"));
        user.setRoles(List.of("ROLE_USER"));
        user.setActive(true);
        user.setEmailVerified(true);
        userRepository.save(user);

        // 2. Login
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("login@example.com");
        loginRequest.setPassword("MyPassword123!");

        // 3. Assert
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andDo(print())
                .andExpect(status().isOk())
                // We check for existence, not null. If DTO is snake_case, this might fail, so we check data root first.
                .andExpect(jsonPath("$.data", notNullValue()))
                .andExpect(jsonPath("$.data.accessToken").isNotEmpty())
                .andExpect(cookie().exists("refresh_token"));
    }

    @Test
    @DisplayName("Should Fail Login with Wrong Password")
    void login_Failure_WrongPassword() throws Exception {
        User user = new User();
        user.setFullName("Wrong Pass User");
        user.setEmail("wrongpass@example.com");
        user.setPassword(passwordEncoder.encode("CorrectPass!"));
        user.setRoles(List.of("ROLE_USER"));
        user.setActive(true);
        user.setEmailVerified(true);
        userRepository.save(user);

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("wrongpass@example.com");
        loginRequest.setPassword("WrongPass!");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andDo(print())
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Should Refresh Token using Valid Cookie")
    void refreshToken_Success() throws Exception {
        // 1. Seed User
        User user = new User();
        user.setFullName("Refresh User");
        user.setEmail("refresh@example.com");
        user.setPassword(passwordEncoder.encode("Pass123!"));
        user.setRoles(List.of("ROLE_USER"));
        user.setActive(true);
        user.setEmailVerified(true);
        userRepository.save(user);

        // 2. Login to get Cookie
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("refresh@example.com");
        loginRequest.setPassword("Pass123!");

        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        Cookie refreshCookie = loginResult.getResponse().getCookie("refresh_token");

        // 3. Refresh using Cookie
        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(refreshCookie))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.accessToken").isNotEmpty());
    }
}
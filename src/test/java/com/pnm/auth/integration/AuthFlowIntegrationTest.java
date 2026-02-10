package com.pnm.auth.integration;

import com.pnm.auth.AbstractIntegrationTest;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.entity.VerificationToken;
import com.pnm.auth.dto.request.LoginRequest;
import com.pnm.auth.dto.request.RegisterRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class AuthFlowIntegrationTest extends AbstractIntegrationTest {

    @Test
    @DisplayName("Full Cycle: Register -> Verify Email -> Login")
    void shouldRegisterVerifyAndLoginSuccessfully() throws Exception {
        // REGISTER
        String email = "integration.test@example.com";
        String password = "StrongPassword123!";

        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setFullName("Integration User");
        registerRequest.setEmail(email);
        registerRequest.setPassword(password);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.success").value(true));

        // DB CHECK
        User user = userRepository.findByEmail(email).orElseThrow();

        assertThat(user.getEmailVerified()).as("User should not be verified initially").isFalse();

        // Retrieve the token
        VerificationToken tokenEntity = verificationTokenRepository.findAll().stream()
                .filter(t -> t.getUser().getId().equals(user.getId()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Verification token not found in DB"));

        // VERIFY EMAIL
        mockMvc.perform(get("/api/auth/verify") // Double check this endpoint path in your Controller
                        .param("token", tokenEntity.getToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));

        // DB Re-check
        User verifiedUser = userRepository.findById(user.getId()).orElseThrow();
        assertThat(verifiedUser.getEmailVerified()).as("User should be verified now").isTrue();

        // LOGIN
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail(email);
        loginRequest.setPassword(password);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.accessToken").isNotEmpty());
    }
}
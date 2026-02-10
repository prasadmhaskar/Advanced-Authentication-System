package com.pnm.auth.integration;

import com.pnm.auth.AbstractIntegrationTest;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.entity.VerificationToken;
import com.pnm.auth.dto.request.ForgotPasswordRequest;
import com.pnm.auth.dto.request.LoginRequest;
import com.pnm.auth.dto.request.ResetPasswordRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class PasswordResetIntegrationTest extends AbstractIntegrationTest {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    @DisplayName("Should successfully request password reset and change password")
    void shouldResetPasswordSuccessfully() throws Exception {
        // Create active user with OLD password
        String email = "reset.test@example.com";
        String oldPassword = "OldPassword123!";
        String newPassword = "NewStrongPassword123!";

        User user = new User();
        user.setEmail(email);
        user.setFullName("Reset User");
        user.setPassword(passwordEncoder.encode(oldPassword));
        user.setEmailVerified(true);
        user.setMfaEnabled(false);
        user = userRepository.save(user);

        final Long userId = user.getId();

        // FORGOT PASSWORD REQUEST
        ForgotPasswordRequest forgotRequest = new ForgotPasswordRequest();
        forgotRequest.setEmail(email);

        mockMvc.perform(post("/api/auth/forgot-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(forgotRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("If your email is registered, password reset link has been dispatched to your email address."));

        // RETRIEVE TOKEN (Simulate Email Link)
        // Since we saved the user manually, this is the ONLY token they have.
        VerificationToken resetTokenEntity = verificationTokenRepository.findAll().stream()
                .filter(t -> t.getUser().getId().equals(userId))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Password reset token not generated in DB"));

        assertThat(resetTokenEntity.getUsedAt()).as("Token should be unused initially").isNull();

        // RESET PASSWORD
        ResetPasswordRequest resetRequest = new ResetPasswordRequest();
        resetRequest.setToken(resetTokenEntity.getToken());
        resetRequest.setNewPassword(newPassword);

        mockMvc.perform(post("/api/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(resetRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));

        // DB Verification
        boolean tokenExists = verificationTokenRepository.existsById(resetTokenEntity.getId());
        assertThat(tokenExists).as("Token should be deleted after successful reset").isFalse();

        // Verify Password Update
        User updatedUser = userRepository.findById(userId).orElseThrow();
        assertThat(passwordEncoder.matches(newPassword, updatedUser.getPassword())).as("DB Password should match new password").isTrue();
        assertThat(passwordEncoder.matches(oldPassword, updatedUser.getPassword())).as("DB Password should NOT match old password").isFalse();

        // LOGIN WITH NEW PASSWORD
        LoginRequest loginNew = new LoginRequest();
        loginNew.setEmail(email);
        loginNew.setPassword(newPassword);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginNew)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));

        // LOGIN WITH OLD PASSWORD
        LoginRequest loginOld = new LoginRequest();
        loginOld.setEmail(email);
        loginOld.setPassword(oldPassword);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginOld)))
                .andExpect(status().isUnauthorized()) // Or 400 depending on your Exception Handler
                .andExpect(jsonPath("$.success").value(false));
    }
}
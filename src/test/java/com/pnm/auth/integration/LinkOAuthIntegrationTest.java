package com.pnm.auth.integration;

import com.pnm.auth.AbstractIntegrationTest;
import com.pnm.auth.domain.entity.AccountLinkToken;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthProviderType;
import com.pnm.auth.dto.request.LinkOAuthRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class LinkOAuthIntegrationTest extends AbstractIntegrationTest {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    @DisplayName("Should successfully link OAuth account with valid token")
    void shouldLinkAccountSuccessfully() throws Exception {
        // User
        String email = "link@test.com";
        User user = new User();
        user.setEmail(email);
        user.setFullName("Link User");
        user.setPassword(passwordEncoder.encode("Password123!"));
        user.setEmailVerified(true);
        user.setMfaEnabled(false);
        user = userRepository.save(user);

        // Create Link Token (Simulate "LINK_REQUIRED" state from OAuth Service)
        String linkTokenString = UUID.randomUUID().toString();
        AccountLinkToken linkToken = new AccountLinkToken();
        linkToken.setToken(linkTokenString);
        linkToken.setUser(user);
        linkToken.setProviderToLink(AuthProviderType.GOOGLE);
        linkToken.setProviderUserId("google-999");
        linkToken.setExpiresAt(LocalDateTime.now().plusMinutes(10));
        accountLinkTokenRepository.save(linkToken);

        // Call /link-oauth
        LinkOAuthRequest request = new LinkOAuthRequest();
        request.setLinkToken(linkTokenString);
        request.setProvider(AuthProviderType.GOOGLE);

        mockMvc.perform(post("/api/auth/link-oauth")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("Account linked successfully"))
                .andExpect(jsonPath("$.data.accessToken").isNotEmpty());

        // ASSERT
        // Check Provider Linked in DB using correct repository method
        boolean providerLinked = userOAuthProviderRepository.findByUser_Id(user.getId()).stream()
                .anyMatch(p -> p.getProviderType() == AuthProviderType.GOOGLE && p.getProviderId().equals("google-999"));
        assertThat(providerLinked).as("Google provider should be linked to user").isTrue();

        assertThat(accountLinkTokenRepository.findByToken(linkTokenString)).isEmpty();
    }

    @Test
    @DisplayName("Should fail linking when provider does not match token")
    void shouldFailLinkingWithProviderMismatch() throws Exception {
        // SETUP
        User user = new User();
        user.setEmail("fail@test.com");
        user.setFullName("Fail User"); // <--- FIX: Add this
        user.setPassword(passwordEncoder.encode("Password123!"));
        user.setEmailVerified(true);
        user.setMfaEnabled(false);
        userRepository.save(user);

        String linkTokenString = UUID.randomUUID().toString();
        AccountLinkToken linkToken = new AccountLinkToken();
        linkToken.setToken(linkTokenString);
        linkToken.setUser(user);
        linkToken.setProviderToLink(AuthProviderType.GITHUB); // Token is for GITHUB
        linkToken.setProviderUserId("gh-111");
        linkToken.setExpiresAt(LocalDateTime.now().plusMinutes(10));
        accountLinkTokenRepository.save(linkToken);

        // EXECUTE with WRONG Provider (Google)
        LinkOAuthRequest request = new LinkOAuthRequest();
        request.setLinkToken(linkTokenString);
        request.setProvider(AuthProviderType.GOOGLE); // Mismatch!

        mockMvc.perform(post("/api/auth/link-oauth")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized()) // InvalidTokenException usually maps to 401 or 400
                .andExpect(jsonPath("$.success").value(false));
    }
}
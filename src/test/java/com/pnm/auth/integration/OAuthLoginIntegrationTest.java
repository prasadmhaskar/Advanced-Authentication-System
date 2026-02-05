package com.pnm.auth.integration;

import com.pnm.auth.AbstractIntegrationTest;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.domain.enums.AuthProviderType;
import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.security.oauth.OAuth2ServiceImpl;
import com.pnm.auth.web.context.RequestContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collections;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class OAuthLoginIntegrationTest extends AbstractIntegrationTest {

    @Autowired
    private OAuth2ServiceImpl oAuth2Service;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    @DisplayName("Should create new user on first OAuth login")
    void shouldCreateNewUserOnFirstOAuthLogin() {
        // 1. SETUP: Mock OAuth2User (Google)
        String email = "oauth.new@test.com";
        Map<String, Object> attributes = Map.of(
                "sub", "google-12345",
                "email", email,
                "name", "OAuth User",
                "picture", "http://pic.com"
        );
        OAuth2User oAuth2User = new DefaultOAuth2User(
                Collections.emptySet(), attributes, "sub"
        );

        // 2. EXECUTE
        RequestContext ctx = new RequestContext("127.0.0.1", "Test-Agent", "/login/oauth2/code/google");
        AuthenticationResult result = oAuth2Service.handleOAuth2LoginRequest(oAuth2User, "google", ctx);

        // 3. ASSERT
        assertThat(result.getOutcome()).isEqualTo(AuthOutcome.SUCCESS);
        assertThat(result.getAccessToken()).isNotNull();
        assertThat(result.getRefreshToken()).isNotNull();

        // DB Verification
        User savedUser = userRepository.findByEmail(email).orElseThrow();
        assertThat(savedUser.getFullName()).isEqualTo("OAuth User");
        assertThat(savedUser.getEmailVerified()).isTrue();

        // FIXED: Use findByUser_Id and check list size
        var providers = userOAuthProviderRepository.findByUser_Id(savedUser.getId());

        assertThat(providers).as("User should have linked OAuth providers").isNotEmpty();
        assertThat(providers.get(0).getProviderType()).isEqualTo(AuthProviderType.GOOGLE);
        assertThat(providers.get(0).getProviderId()).isEqualTo("google-12345"); // Matches 'sub' from mock attributes
    }

    @Test
    @DisplayName("Should require linking if email exists with different provider")
    void shouldRequireLinkingForExistingUser() {
        // 1. SETUP: Existing Password User
        String email = "conflict@test.com";
        User user = new User();
        user.setEmail(email);
        user.setFullName("Existing User");
        user.setPassword(passwordEncoder.encode("Password123!"));
        user.setEmailVerified(true);
        user.setMfaEnabled(false);
        userRepository.save(user);

        // 2. EXECUTE: Try login with GitHub (same email)
        Map<String, Object> attributes = Map.of(
                "id", 98765,
                "email", email,
                "name", "GitHub User"
        );
        OAuth2User oAuth2User = new DefaultOAuth2User(
                Collections.emptySet(), attributes, "id"
        );

        RequestContext ctx = new RequestContext("127.0.0.1", "Test-Agent", "/login/oauth2/code/github");
        AuthenticationResult result = oAuth2Service.handleOAuth2LoginRequest(oAuth2User, "github", ctx);

        // 3. ASSERT
        assertThat(result.getOutcome()).isEqualTo(AuthOutcome.LINK_REQUIRED);
        assertThat(result.getLinkToken()).isNotNull();
        assertThat(result.getAttemptedProvider()).isEqualTo(AuthProviderType.GITHUB);

        // DB Verification: Link Token created
        assertThat(accountLinkTokenRepository.findByToken(result.getLinkToken())).isPresent();
    }
}
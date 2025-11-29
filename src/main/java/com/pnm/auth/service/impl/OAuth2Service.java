package com.pnm.auth.service.impl;

import com.pnm.auth.dto.response.AuthResponse;
import com.pnm.auth.entity.RefreshToken;
import com.pnm.auth.entity.User;
import com.pnm.auth.enums.AuthProviderType;
import com.pnm.auth.exception.UserAlreadyExistsException;
import com.pnm.auth.repository.RefreshTokenRepository;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.util.JwtUtil;
import com.pnm.auth.util.OAuth2Util;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class OAuth2Service {

    private final OAuth2Util oAuth2Util;
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;

    public AuthResponse handleOAuth2LoginRequest(OAuth2User oAuth2User, String registrationId) {

        log.info("OAuth2Service.handleOAuth2LoginRequest(): started provider={} ", registrationId);
        AuthProviderType authProviderType = oAuth2Util.getProviderTypeFromRegistrationId(registrationId);
        String providerId = oAuth2Util.determineProviderIdFromOAuth2User(oAuth2User, registrationId);
        String email = oAuth2User.getAttribute("email");
        log.info("OAuth2Service.handleOAuth2LoginRequest(): login attempt email={} providerId={} providerType={}",
                email, providerId, authProviderType);

        User user = userRepository.findByProviderIdAndAuthProviderType(providerId, authProviderType).orElse(null);
        User emailUser = (email != null) ? userRepository.findByEmail(email).orElse(null) : null;

        if (user == null && emailUser == null) {
            // Create new user
            log.info("OAuth2Service.handleOAuth2LoginRequest(): creating new user for email={} provider={}", email, authProviderType);
            String username = oAuth2Util.determineUsernameFromOAuth2User(oAuth2User, registrationId);
            user = new User();
            user.setFullName(username);
            String randomPassword = UUID.randomUUID().toString();
            user.setPassword(randomPassword);
            user.setEmail(email);
            user.setProviderId(providerId);
            user.setAuthProviderType(authProviderType);
            user.setEmailVerified(true);
            user.setRoles(List.of("USER"));
            userRepository.save(user);
        } else if (user == null && emailUser != null) {
            // Email exists
            log.warn("OAuth2Service.handleOAuth2LoginRequest(): account exists for email={} (needs merging)", email);
            throw new UserAlreadyExistsException("The email: "+email+" is already registered. Do you want to merge both accounts?");
        } else {
            // Existing OAuth2 user (user != null)
            log.info("OAuth2Service.handleOAuth2LoginRequest(): existing OAuth user login for email={}", email);

            if (email != null && (user.getEmail() == null || !user.getEmail().equals(email))) {
                user.setEmail(email);
                userRepository.save(user);
            }
        }

        String accessToken = jwtUtil.generateAccessToken(user);
        String refreshToken = jwtUtil.generateRefreshToken(user);

        refreshTokenRepository.save(new RefreshToken(refreshToken, user, LocalDateTime.now()));

        log.info("OAuth2Service.handleOAuth2LoginRequest(): successful for email={}", user.getEmail());

        return new AuthResponse("Login successful using OAuth2", accessToken, refreshToken);
    }
}

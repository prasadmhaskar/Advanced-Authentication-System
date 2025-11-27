package com.pnm.auth.util;

import com.pnm.auth.enums.AuthProviderType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2Util {


    public AuthProviderType getProviderTypeFromRegistrationId(String registrationId){
        return switch (registrationId.toLowerCase()) {
            case "google" -> AuthProviderType.GOOGLE;
            case "github" -> AuthProviderType.GITHUB;
            case "facebook" -> AuthProviderType.FACEBOOK;
            case "twitter" -> AuthProviderType.TWITTER;
            default -> throw new IllegalArgumentException("Unsupported OAuth2 provider: " + registrationId);
        };
    }

    public String determineProviderIdFromOAuth2User(OAuth2User oAuth2User , String registrationId){
        String providerId = switch (registrationId.toLowerCase()) {
            case "google" -> oAuth2User.getAttribute("sub");
            case "github" -> oAuth2User.getAttribute("id").toString();
            default -> {
                log.error("Unsupported OAuth2 provider: {}", registrationId);
                throw new IllegalArgumentException("Unsupported OAuth2 provider: " + registrationId);
            }
        };

        if(providerId == null || providerId.isEmpty()){
            log.error("Unable to determine providerId for given provider: {}",registrationId);
            throw new IllegalArgumentException("Unable to determine providerId for OAuth2 login");
        }
        return providerId;
    }


    public String determineUsernameFromOAuth2User(OAuth2User oAuth2User, String registrationId) {
        String username;
        String email = oAuth2User.getAttribute("email");
        String emailUsername = null;

        if (email != null) {
            int atIndex = email.indexOf('@');
            emailUsername = email.substring(0, atIndex);
        }
        switch (registrationId.toLowerCase()) {
            case "google":
                // Try given_name, then full name, then email prefix, then sub
                username = oAuth2User.getAttribute("given_name");
                if (username == null || username.isEmpty()) {
                    username = oAuth2User.getAttribute("name");
                }
                if (username == null || username.isEmpty()) {
                    username = emailUsername;
                }
                if (username == null || username.isEmpty()) {
                    username = oAuth2User.getAttribute("sub");
                }
                break;

            case "github":
                // GitHub provides "login" as username
                username = oAuth2User.getAttribute("login");
                if (username == null || username.isEmpty()) {
                    username = emailUsername;
                }
                break;

            default:
                // For other providers, fall back to email prefix
                username = emailUsername;
        }
        return username;
    }
}

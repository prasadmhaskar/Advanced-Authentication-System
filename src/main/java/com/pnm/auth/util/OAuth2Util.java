package com.pnm.auth.util;

import com.pnm.auth.domain.enums.AuthProviderType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;




@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2Util {

    public AuthProviderType getProviderTypeFromRegistrationId(String registrationId) {
        log.info("OAuth2Util.getProviderTypeFromRegistrationId: registrationId={}", registrationId);

        return switch (registrationId.toLowerCase()) {
            case "google" -> {
                log.info("OAuth2Util: Provider resolved as GOOGLE");
                yield AuthProviderType.GOOGLE;
            }
            case "github" -> {
                log.info("OAuth2Util: Provider resolved as GITHUB");
                yield AuthProviderType.GITHUB;
            }
            case "facebook" -> {
                log.info("OAuth2Util: Provider resolved as FACEBOOK");
                yield AuthProviderType.FACEBOOK;
            }
            case "twitter" -> {
                log.info("OAuth2Util: Provider resolved as TWITTER");
                yield AuthProviderType.TWITTER;
            }
            default -> {
                log.error("OAuth2Util: Unsupported OAuth2 provider={}", registrationId);
                throw new IllegalArgumentException("Unsupported OAuth2 provider: " + registrationId);
            }
        };
    }

    public String determineProviderIdFromOAuth2User(OAuth2User oAuth2User, String registrationId) {
        log.info("OAuth2Util.determineProviderId: Extracting providerId from provider={}", registrationId);

        String providerId = switch (registrationId.toLowerCase()) {
            case "google" -> oAuth2User.getAttribute("sub");
            case "github" -> oAuth2User.getAttribute("id") != null ?
                    oAuth2User.getAttribute("id").toString() : null;
            default -> {
                log.error("OAuth2Util: Unsupported OAuth2 provider={}", registrationId);
                throw new IllegalArgumentException("Unsupported OAuth2 provider: " + registrationId);
            }
        };

        if (providerId == null || providerId.isEmpty()) {
            log.error("OAuth2Util.determineProviderId: providerId is NULL for provider={}", registrationId);
            throw new IllegalArgumentException("Unable to determine providerId for OAuth2 login");
        }

        // Log safe prefix (avoid logging entire providerId)
        String prefix = providerId.length() > 8 ? providerId.substring(0, 8) : providerId;
        log.info("OAuth2Util.determineProviderId: providerId extracted tokenPrefix={}", prefix);

        return providerId;
    }


    public String determineUsernameFromOAuth2User(OAuth2User oAuth2User, String registrationId) {

        log.info("OAuth2Util.determineUsername: Started provider={}", registrationId);

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
        log.info("OAuth2Util.determineUsername: Extracted username={}", username);
        return username;
    }
}


package com.pnm.auth.security.oauth;


import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.entity.UserOAuthProvider;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.domain.enums.AuthProviderType;
import com.pnm.auth.dto.result.ResolveOAuthResult;
import com.pnm.auth.exception.custom.OAuth2LoginFailedException;
import com.pnm.auth.repository.UserOAuthProviderRepository;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.service.ipmonitoring.IpMonitoringService;
import com.pnm.auth.util.OAuth2Util;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class OAuthPersistenceService {

    private final UserRepository userRepository;
    private final UserOAuthProviderRepository oAuthProviderRepository;
    private final AccountLinkTokenService accountLinkTokenService;
    private final OAuth2Util oAuth2Util;
    private final IpMonitoringService ipMonitoringService;

    @Transactional
    public ResolveOAuthResult resolveOrCreateUser(OAuth2User oAuth2User, AuthProviderType providerType, String providerId, String ip, String userAgent) {

        String email = oAuth2User.getAttribute("email");
        if (email == null) {
            throw new OAuth2LoginFailedException("Provider did not supply email");
        }

        // 1️⃣ Provider already linked? -> Success
        Optional<UserOAuthProvider> provider = oAuthProviderRepository
                .findByProviderTypeAndProviderId(providerType, providerId);

        if (provider.isPresent()) {
            return ResolveOAuthResult.builder()
                    .outcome(AuthOutcome.SUCCESS)
                    .user(provider.get().getUser())
                    .build();
        }

        // 2️⃣ Email exists but provider NOT linked? -> LINK_REQUIRED
        Optional<User> emailUser = userRepository.findByEmail(email);

        if (emailUser.isPresent()) {
            User existingUser = emailUser.get();
            AuthProviderType existingProvider = existingUser.getAuthProviders()
                    .iterator().next().getProviderType();

            // Create Link Token (Atomic with this check)
            String linkToken = accountLinkTokenService.createLinkToken(
                    existingUser, providerType, providerId
            );

            log.warn("OAuthPersistence: Linking required for email={}", email);

            return ResolveOAuthResult.builder()
                    .outcome(AuthOutcome.LINK_REQUIRED)
                    .email(email)
                    .existingProvider(existingProvider)
                    .linkToken(linkToken)
                    .build();
        }

        // 3️⃣ New OAuth user -> Create & Link
        log.info("OAuthPersistence: Detected new user creation for email={}", email);

        // 🛑 PREVENTATIVE CHECK (Inside Transaction)
        // We only check this if we are SURE it's a new registration.
        // This prevents blocking existing users on shared IPs.
        ipMonitoringService.checkRegistrationEligibility(ip, userAgent);

        // 3️⃣ New OAuth user -> Create & Link
        User user = new User();
        user.setFullName(oAuth2Util.determineUsernameFromOAuth2User(oAuth2User, providerType.name()));
        user.setEmail(email);
        user.setEmailVerified(true);
        user.setRoles(List.of("ROLE_USER"));
        user.setActive(true);

        user.linkProvider(providerType, providerId);

        userRepository.save(user);

        log.info("OAuthPersistence: New user created for email={}", email);

        return ResolveOAuthResult.builder()
                .outcome(AuthOutcome.SUCCESS)
                .user(user)
                .isNewUser(true)
                .build();
    }
}

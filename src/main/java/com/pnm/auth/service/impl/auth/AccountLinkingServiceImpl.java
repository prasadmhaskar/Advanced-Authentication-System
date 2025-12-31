package com.pnm.auth.service.impl.auth;

import com.pnm.auth.domain.entity.AccountLinkToken;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.entity.UserOAuthProvider;
import com.pnm.auth.domain.enums.AuthProviderType;
import com.pnm.auth.dto.request.LinkOAuthRequest;
import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.dto.result.LinkingResult;
import com.pnm.auth.exception.custom.AccountBlockedException;
import com.pnm.auth.exception.custom.InvalidTokenException;
import com.pnm.auth.repository.AccountLinkTokenRepository;
import com.pnm.auth.repository.UserOAuthProviderRepository;
import com.pnm.auth.service.auth.AccountLinkingService;
import com.pnm.auth.service.auth.TokenService;
import com.pnm.auth.service.auth.VerificationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@Slf4j
@RequiredArgsConstructor
public class AccountLinkingServiceImpl implements AccountLinkingService {

    private final AccountLinkTokenRepository accountLinkTokenRepository;
    private final UserOAuthProviderRepository providerRepository;
    private final TokenService tokenService;
    private final VerificationService verificationService;

    @Override
    @Transactional
    public LinkingResult linkAccount(LinkOAuthRequest request) {
        // 1️⃣ Load & validate link token
        AccountLinkToken linkToken = accountLinkTokenRepository
                .findByToken(request.getLinkToken())
                .orElseThrow(() -> new InvalidTokenException("Invalid link token"));

        if (linkToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            accountLinkTokenRepository.delete(linkToken);
            throw new InvalidTokenException("Link token expired");
        }

        if (linkToken.getProviderToLink() != request.getProvider()) {
            throw new InvalidTokenException("Invalid provider for link token");
        }

        User user = linkToken.getUser();

        if (!user.isActive()) {
            throw new AccountBlockedException("Your account has been blocked.");
        }

        // 2️⃣ Idempotency & Save Provider
        if (!user.hasProvider(request.getProvider())) {
            UserOAuthProvider provider = UserOAuthProvider.builder()
                    .providerType(linkToken.getProviderToLink())
                    .providerId(linkToken.getProviderUserId())
                    .linkedAt(LocalDateTime.now())
                    .active(true)
                    .user(user)
                    .build();
            providerRepository.save(provider);
        }

        // 3️⃣ Cleanup
        accountLinkTokenRepository.delete(linkToken);

        // 4️⃣ Generate Auto-Login Tokens
        AuthenticationResult auth = tokenService.generateTokens(user);

        // 5️⃣ Check if Password Setup is needed (Create token here within transaction)
        String passwordResetToken = null;
        if (request.getProvider() == AuthProviderType.EMAIL && user.getPassword() == null) {
            passwordResetToken = verificationService.createVerificationToken(user, "PASSWORD_RESET");
        }

        return LinkingResult.builder()
                .user(user)
                .authTokens(auth)
                .passwordResetToken(passwordResetToken)
                .build();
    }
}

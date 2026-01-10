package com.pnm.auth.security.oauth;

import com.pnm.auth.domain.entity.AccountLinkToken;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthProviderType;
import com.pnm.auth.exception.custom.InvalidTokenException;
import com.pnm.auth.repository.AccountLinkTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AccountLinkTokenService {

    private final AccountLinkTokenRepository accountLinkTokenRepository;

    @Transactional
    public String createLinkToken(
            User user,
            AuthProviderType providerToLink,
            String providerUserId
    ) {
        log.info("AccountLinkToken.createLinkToken(): started userId={} provider={}", user.getId(), providerToLink);

        // Invalidate old tokens
        accountLinkTokenRepository.deleteByUserId(user.getId());

        // Create new token
        String token = UUID.randomUUID().toString();

        AccountLinkToken linkToken = AccountLinkToken.builder()
                .token(token)
                .user(user)
                .providerToLink(providerToLink)
                .providerUserId(providerUserId)
                .expiresAt(LocalDateTime.now().plusMinutes(10))
                .createdAt(LocalDateTime.now())
                .build();

        accountLinkTokenRepository.save(linkToken);

        log.info("AccountLinkToken.createLinkToken(): created userId={} provider={}", user.getId(), providerToLink);

        return token;
    }

    public AccountLinkToken validate(String token) {

        log.info("AccountLinkToken.validate(): started");

        AccountLinkToken linkToken = accountLinkTokenRepository.findByToken(token)
                .orElseThrow(() -> new InvalidTokenException("Invalid link token"));

        if (linkToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            accountLinkTokenRepository.delete(linkToken);
            throw new InvalidTokenException("Link token expired");
        }

        log.info("AccountLinkToken.validate(): finished");

        return linkToken;
    }
}


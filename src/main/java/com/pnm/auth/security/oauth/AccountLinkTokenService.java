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

    private final AccountLinkTokenRepository repository;

    @Transactional
    public String createLinkToken(
            User user,
            AuthProviderType providerToLink,
            String providerUserId
    ) {

        // Invalidate old tokens
        repository.deleteByUserId(user.getId());

        String token = UUID.randomUUID().toString();

        AccountLinkToken linkToken = AccountLinkToken.builder()
                .token(token)
                .user(user)
                .providerToLink(providerToLink)
                .providerUserId(providerUserId)
                .expiresAt(LocalDateTime.now().plusMinutes(10))
                .createdAt(LocalDateTime.now())
                .build();

        repository.save(linkToken);

        log.info(
                "AccountLinkToken created userId={} provider={} tokenPrefix={}",
                user.getId(),
                providerToLink,
                token.substring(0, 8)
        );

        return token;
    }

    public AccountLinkToken validate(String token) {

        AccountLinkToken linkToken = repository.findByToken(token)
                .orElseThrow(() -> new InvalidTokenException("Invalid link token"));

        if (linkToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            repository.delete(linkToken);
            throw new InvalidTokenException("Link token expired");
        }

        return linkToken;
    }

    public void consume(AccountLinkToken token) {
        repository.delete(token);
    }
}


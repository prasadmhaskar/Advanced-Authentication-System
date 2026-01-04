package com.pnm.auth.repository;

import com.pnm.auth.domain.entity.UserOAuthProvider;
import com.pnm.auth.domain.enums.AuthProviderType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserOAuthProviderRepository
        extends JpaRepository<UserOAuthProvider, Long> {

    Optional<UserOAuthProvider> findByProviderTypeAndProviderId(
            AuthProviderType providerType,
            String providerId
    );

    boolean existsByUserIdAndProviderType(Long userId, AuthProviderType providerType);

    void deleteByUserId(Long userId);
}


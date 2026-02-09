package com.pnm.auth.repository;

import com.pnm.auth.domain.entity.UserOAuthProvider;
import com.pnm.auth.domain.enums.AuthProviderType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface UserOAuthProviderRepository extends JpaRepository<UserOAuthProvider, Long> {

    Optional<UserOAuthProvider> findByProviderTypeAndProviderId(AuthProviderType providerType, String providerId);

    void deleteByUserId(Long userId);

    List<UserOAuthProvider> findByUser_Id(Long userId);
}


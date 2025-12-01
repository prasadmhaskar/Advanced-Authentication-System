package com.pnm.auth.repository;

import com.pnm.auth.entity.User;
import com.pnm.auth.enums.AuthProviderType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long>, JpaSpecificationExecutor<User> {
    Optional<User> findByEmail(String email);
    Optional<User> findByProviderIdAndAuthProviderType(String providerId, AuthProviderType authProviderType);
}

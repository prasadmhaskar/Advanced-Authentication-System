package com.pnm.auth.repository;

import com.pnm.auth.domain.entity.AccountLinkToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AccountLinkTokenRepository extends JpaRepository<AccountLinkToken, Long> {

    Optional<AccountLinkToken> findByToken(String token);

    void deleteByUserId(Long userId);
}


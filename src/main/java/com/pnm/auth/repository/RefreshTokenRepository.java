package com.pnm.auth.repository;

import com.pnm.auth.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);

    void deleteByToken(String token);

    void deleteAllByUserId(Long id);

    @Modifying
    @Query("UPDATE RefreshToken r SET r.invalidated = true WHERE r.user.id = :userId")
    void invalidateAllForUser(Long userId);
}

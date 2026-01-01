package com.pnm.auth.repository;

import com.pnm.auth.domain.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);

    void deleteByToken(String token);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
    UPDATE RefreshToken rt
    SET rt.invalidated = true
    WHERE rt.user.id = :userId""")
    void invalidateAllForUser(@Param("userId") Long userId);

    // 1. Count active sessions for a user
    @Query("SELECT COUNT(t) FROM RefreshToken t WHERE t.user.id = :userId")
    long countByUserId(@Param("userId") Long userId);

    // 2. Find the oldest session ID (to delete it)
    @Query("SELECT t.id FROM RefreshToken t WHERE t.user.id = :userId ORDER BY t.createdAt ASC LIMIT 1")
    Optional<Long> findOldestTokenId(@Param("userId") Long userId);

    @Modifying
    @Query("DELETE FROM RefreshToken t WHERE t.user.id = :userId")
    void deleteByUserId(@Param("userId") Long userId); // Optional: for "Logout All"

}

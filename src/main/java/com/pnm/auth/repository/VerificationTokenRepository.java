package com.pnm.auth.repository;

import com.pnm.auth.domain.entity.VerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface VerificationTokenRepository extends JpaRepository<VerificationToken, Long> {

    Optional<VerificationToken> findByToken(String token);

    Optional<VerificationToken> findByTokenAndUsedAtIsNull(String token);

    void deleteByToken(String token);

    @Modifying
    @Query("""
UPDATE VerificationToken t
SET t.usedAt = CURRENT_TIMESTAMP
WHERE t.user.id = :userId
AND t.type = :type
AND t.usedAt IS NULL
""")
    void invalidateUnusedTokens(@Param("userId") Long userId, @Param("type") String type);

    @Modifying
    @Query("""
        DELETE FROM VerificationToken t
        WHERE t.usedAt IS NOT NULL
          AND t.usedAt < :cutoff
    """)
    int deleteUsedTokensBefore(@Param("cutoff") LocalDateTime cutoff);

    @Modifying
    @Query("""
        DELETE FROM VerificationToken t
        WHERE t.usedAt IS NULL
          AND t.expiresAt < :cutoff
    """)
    int deleteExpiredUnusedTokensBefore(@Param("cutoff") LocalDateTime cutoff);


    // VerificationTokenRepository.java
    @Modifying
    @Query("UPDATE VerificationToken t SET t.usedAt = CURRENT_TIMESTAMP WHERE t.id = :id AND t.usedAt IS NULL")
    int markAsUsed(@Param("id") Long id);

    void deleteByUserId(Long userId);

}

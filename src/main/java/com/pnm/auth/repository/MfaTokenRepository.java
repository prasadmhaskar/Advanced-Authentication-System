package com.pnm.auth.repository;

import com.pnm.auth.domain.entity.MfaToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface MfaTokenRepository extends JpaRepository<MfaToken, Long> {
    @Modifying
    @Transactional
    @Query("UPDATE MfaToken t SET t.used = true WHERE t.user.id = :userId AND t.used = false")
    void markAllUnusedTokensAsUsed(@Param("userId") Long userId);

    Optional<MfaToken> findByIdAndUsedFalse(Long id);

    @Query("SELECT t FROM MfaToken t WHERE t.user.id = :userId AND t.used = false AND t.expiresAt > :now")
    List<MfaToken> findValidTokens(@Param("userId") Long userId, @Param("now") LocalDateTime now);

    // ✅ Cleanup: used tokens older than X time
    @Modifying
    @Query("""
        DELETE FROM MfaToken t
        WHERE t.used = true
          AND t.expiresAt < :cutoff
    """)
    int deleteUsedTokensBefore(@Param("cutoff") LocalDateTime cutoff);

    // ✅ Cleanup: expired & unused tokens
    @Modifying
    @Query("""
        DELETE FROM MfaToken t
        WHERE t.used = false
          AND t.expiresAt < :cutoff
    """)
    int deleteExpiredUnusedTokensBefore(@Param("cutoff") LocalDateTime cutoff);

    @Modifying
    @Query("UPDATE MfaToken t SET t.used = true WHERE t.id = :id AND t.used = false")
    int markAsUsed(@Param("id") Long id);

    void deleteByUserId(Long userId);

}

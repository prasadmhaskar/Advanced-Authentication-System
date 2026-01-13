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
    @Query("UPDATE RefreshToken rt SET rt.invalidated = true WHERE rt.user.id = :userId")
    void invalidateAllForUser(@Param("userId") Long userId);

    // 1. Count active sessions for a user
    @Query("SELECT COUNT(t) FROM RefreshToken t WHERE t.user.id = :userId")
    long countByUserId(@Param("userId") Long userId);

    void deleteByUserId(@Param("userId") Long userId);

    @Modifying
    @Query("UPDATE RefreshToken t SET t.used = true WHERE t.token = :token AND t.used = false")
    int markAsUsed(@Param("token") String token);

    @Modifying
    @Query("""
UPDATE RefreshToken r
SET r.invalidated = true
WHERE r.user.id = :userId
AND r.deviceSignature <> :deviceSignature
""")
    void invalidateAllExceptCurrentDevice(
            @Param("userId") Long userId,
            @Param("deviceSignature") String deviceSignature
    );

    @Modifying
    @Query(value = """
        DELETE FROM user_refresh_tokens
        WHERE user_id = :userId
        AND id NOT IN (
            SELECT id FROM (
                SELECT id FROM user_refresh_tokens
                WHERE user_id = :userId
                ORDER BY created_at DESC
                LIMIT :limit
            ) tmp
        )
    """, nativeQuery = true)
    void deleteOldestSessions(@Param("userId") Long userId, @Param("limit") int limit);


}

package com.pnm.auth.repository;

import com.pnm.auth.domain.entity.UserIpLog;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

public interface UserIpLogRepository extends JpaRepository<UserIpLog, Long> {

    List<UserIpLog> findTop10ByUserIdOrderByLoginTimeDesc(Long userId);

    boolean existsByUserIdAndIpAddress(Long userId, String ipAddress);

    int countByIpAddress(String ipAddress);

    @Query("select count(u) from UserIpLog u where u.userId = :userId and u.ipAddress = :ip")
    int countByUserIdAndIpAddress(Long userId, String ip);

    UserIpLog findTop1ByUserIdOrderByLoginTimeDesc(Long userId);

    boolean existsByUserIdAndDeviceSignature(Long userId, String deviceSignature);

    int countByDeviceSignature(String deviceSignature);

    @Query("SELECT COUNT(l) FROM UserIpLog l WHERE l.isSuspicious = true AND l.loginTime >= :start")
    long countSuspiciousSince(LocalDateTime start);

    @Query("SELECT COUNT(l) FROM UserIpLog l WHERE l.riskScore >= 80 AND l.loginTime >= :start")
    long countHighRiskSince(LocalDateTime start);

    @Query("""
SELECT COUNT(DISTINCT u.userId)
FROM UserIpLog u
WHERE u.ipAddress = :ip
AND u.userId IS NOT NULL
""")
    int countDistinctUsersByIp(@Param("ip") String ip);

    @Query("""
SELECT COUNT(DISTINCT u.userId)
FROM UserIpLog u
WHERE u.deviceSignature = :deviceSignature
AND u.userId IS NOT NULL
""")
    int countDistinctUsersByDevice(@Param("deviceSignature") String deviceSignature);

    /**
     * NATIVE QUERY: Manually joins 'user_ip_log' with 'users' table.
     * We MUST use native SQL because UserIpLog entity has no @ManyToOne relationship to User.
     * * NOTE: Ensure table names ('user_ip_log', 'users') match your actual DB schema exactly.
     */
    @Query(value = """
        SELECT DISTINCT u.email
        FROM user_ip_log l
        JOIN users u ON l.user_id = u.id
        WHERE l.ip_address = :ip
        """, nativeQuery = true)
    List<String> findDistinctEmailsByIp(@Param("ip") String ip, Pageable pageable);

    void deleteByUserId(Long userId);

}

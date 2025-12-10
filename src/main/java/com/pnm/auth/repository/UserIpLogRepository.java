package com.pnm.auth.repository;

import com.pnm.auth.entity.UserIpLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

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
}

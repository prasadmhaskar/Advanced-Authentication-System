package com.pnm.auth.repository;

import com.pnm.auth.domain.entity.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
    void deleteByTargetUserId(Long userId);
}

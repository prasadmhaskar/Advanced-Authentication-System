package com.pnm.auth.service.audit;

import com.pnm.auth.dto.response.AuditLogResponse;
import com.pnm.auth.dto.response.PagedResponse;
import com.pnm.auth.domain.enums.AuditAction;

public interface AuditService {
    void record(AuditAction action, Long actorUserId, Long targetUserId,
                String description, String ip, String userAgent);

    PagedResponse<AuditLogResponse> getAll(int page, int size);
}

package com.pnm.auth.dto.response;

import com.pnm.auth.domain.entity.AuditLog;
import lombok.*;

import java.time.LocalDateTime;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditLogResponse {

    private Long id;
    private Long actorUserId;
    private Long targetUserId;
    private String action;
    private String description;
    private String ip;
    private String userAgent;
    private LocalDateTime createdAt;

    public static AuditLogResponse fromEntity(AuditLog log) {
        return AuditLogResponse.builder()
                .id(log.getId())
                .actorUserId(log.getActorUserId())
                .targetUserId(log.getTargetUserId())
                .action(log.getAction().name())     // enum → string
                .description(log.getDescription())
                .ip(log.getIp())
                .userAgent(log.getUserAgent())
                .createdAt(log.getCreatedAt())
                .build();
    }
}

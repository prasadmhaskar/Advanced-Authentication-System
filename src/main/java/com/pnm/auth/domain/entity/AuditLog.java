package com.pnm.auth.domain.entity;

import com.pnm.auth.domain.enums.AuditAction;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "audit_logs")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Long actorUserId;      // who performed the action
    private Long targetUserId;     // user affected (can be same)

    @Enumerated(EnumType.STRING)
    private AuditAction action;

    @Column(length = 500)
    private String description;

    private String ip;
    private String userAgent;

    private LocalDateTime createdAt;
}

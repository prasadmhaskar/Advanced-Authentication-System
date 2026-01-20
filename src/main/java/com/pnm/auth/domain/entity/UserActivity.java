package com.pnm.auth.domain.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "user_activity")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserActivity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Long userId;

    private String email;
    private String ipAddress;
    private String userAgent;
    private String status;
    private String message;

    private LocalDateTime createdAt;

    @PrePersist
    public void prePersist() {
        this.createdAt = LocalDateTime.now();
    }

}

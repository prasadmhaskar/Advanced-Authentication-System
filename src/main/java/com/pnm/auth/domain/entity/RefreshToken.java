package com.pnm.auth.domain.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "user_refresh_tokens")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "token_hash", nullable = false, unique = true, length = 64)
    private String tokenHash;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    private LocalDateTime createdAt;

    private String deviceSignature;

    private LocalDateTime expiresAt;

    private boolean used = false;

    private boolean invalidated = false;

    public RefreshToken(String tokenHash, User user, LocalDateTime now) {
        this.tokenHash = tokenHash;
        this.user = user;
        this.createdAt = now;
        this.expiresAt = now.plusDays(60);
    }
}

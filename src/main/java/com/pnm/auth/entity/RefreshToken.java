package com.pnm.auth.entity;

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

    @Column(nullable = false, unique = true)
    private String token;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    private LocalDateTime createdAt;

    private LocalDateTime expiresAt;   // NEW

    private boolean used = false;      // NEW

    private boolean invalidated = false;  // NEW

    public RefreshToken(String refreshToken, User user, LocalDateTime now) {
        this.token = refreshToken;
        this.user = user;
        this.createdAt = now;
        this.expiresAt = now.plusDays(60);  // matching your JWT refresh TTL
    }
}


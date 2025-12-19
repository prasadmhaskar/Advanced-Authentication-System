package com.pnm.auth.domain.entity;

import com.pnm.auth.domain.enums.AuthProviderType;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "account_link_tokens")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AccountLinkToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 100)
    private String token;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AuthProviderType providerToLink;

    @Column(nullable = false)
    private String providerUserId; // Google sub / GitHub id

    @Column(nullable = false)
    private LocalDateTime expiresAt;

    private LocalDateTime createdAt;
}


package com.pnm.auth.domain.entity;

import com.pnm.auth.domain.enums.AuthProviderType;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(
        name = "user_oauth_providers",
        uniqueConstraints = { @UniqueConstraint(columnNames = {"provider_type", "provider_id"}) }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserOAuthProvider {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id")
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(name = "provider_type", nullable = false)
    private AuthProviderType providerType;

    @Column(name = "provider_id", nullable = false)
    private String providerId;

    @Column(nullable = false)
    private Boolean active = true;

    private LocalDateTime linkedAt = LocalDateTime.now();
}



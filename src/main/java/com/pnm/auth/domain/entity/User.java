package com.pnm.auth.domain.entity;

import com.pnm.auth.domain.enums.AuthProviderType;
import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;
import java.util.*;

@Entity
@Table(name = "users")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String fullName;

    @Column(nullable = false, unique = true)
    private String email;

    private String password;

    @Column(nullable = false)
    private Boolean emailVerified = false;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id")
    )
    @Column(name = "role")
    private List<String> roles = new ArrayList<>();;

    @Column(nullable = false)
    private boolean active = true;

    private boolean mfaEnabled = false;

    @OneToMany(
            mappedBy = "user",
            cascade = CascadeType.ALL,
            orphanRemoval = true,
            fetch = FetchType.LAZY
    )
    private Set<UserOAuthProvider> authProviders = new HashSet<>();

    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    @PrePersist
    public void onCreate() {
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    public void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }

    // --------- helper methods ----------
    public void linkProvider(AuthProviderType type, String providerId) {

        if (hasProvider(type)) {
            throw new IllegalStateException("Auth provider already linked: " + type);
        }

        UserOAuthProvider provider = UserOAuthProvider.builder()
                .providerType(type)
                .providerId(providerId)
                .active(true)
                .linkedAt(LocalDateTime.now())
                .build();

        addAuthProvider(provider);
    }

    public boolean hasProvider(AuthProviderType type) {
        return authProviders.stream()
                .anyMatch(p -> p.getProviderType() == type);
    }

    public Optional<UserOAuthProvider> getProvider(AuthProviderType type) {
        return authProviders.stream()
                .filter(p -> p.getProviderType() == type)
                .findFirst();
    }

    private void addAuthProvider(UserOAuthProvider provider) {
        provider.setUser(this);
        this.authProviders.add(provider);
    }
}

package com.pnm.auth.dto.response;

import com.pnm.auth.domain.entity.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserAdminResponse {

    private Long id;
    private String fullName;
    private String email;
    private Boolean emailVerified;
    private List<String> roles;
    private boolean active;
    private boolean mfaEnabled;

    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    // ⭐ NEW
    private List<UserAuthProviderAdminResponse> authProviders;

    public static UserAdminResponse fromEntity(User user) {

        List<UserAuthProviderAdminResponse> providers =
                user.getAuthProviders() == null
                        ? List.of()
                        : user.getAuthProviders()
                        .stream()
                        .map(UserAuthProviderAdminResponse::fromEntity)
                        .toList();

        return UserAdminResponse.builder()
                .id(user.getId())
                .fullName(user.getFullName())
                .email(user.getEmail())
                .emailVerified(user.getEmailVerified())
                .roles(user.getRoles())
                .active(user.isActive())
                .mfaEnabled(user.isMfaEnabled())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .authProviders(providers)
                .build();
    }
}

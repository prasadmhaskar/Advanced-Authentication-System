package com.pnm.auth.dto.response;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.entity.UserOAuthProvider;
import com.pnm.auth.domain.enums.AuthProviderType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserDetailsResponse {

    private String fullName;
    private String email;
    private List<String> roles;

    // ⭐ MULTI PROVIDER
    private List<AuthProviderType> authProviders;

    // Optional but useful for frontend
    private boolean emailLoginEnabled;

    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    public static UserDetailsResponse fromEntity(User user) {

        List<AuthProviderType> providers =
                user.getAuthProviders()
                        .stream()
                        .map(UserOAuthProvider::getProviderType)
                        .toList();

        return UserDetailsResponse.builder()
                .fullName(user.getFullName())
                .email(user.getEmail())
                .roles(user.getRoles())
                .authProviders(providers)
                .emailLoginEnabled(user.hasProvider(AuthProviderType.EMAIL))
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .build();
    }
}



package com.pnm.auth.dto.response;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthProviderType;
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
    private AuthProviderType authProviderType;
    private String providerId;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private boolean active;

    public static UserAdminResponse fromEntity(User user) {
        return UserAdminResponse.builder()
                .id(user.getId())
                .fullName(user.getFullName())
                .email(user.getEmail())
                .emailVerified(user.getEmailVerified())
                .roles(user.getRoles())
                .authProviderType(user.getAuthProviderType())
                .providerId(user.getProviderId())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .active(user.isActive())
                .build();
    }

}

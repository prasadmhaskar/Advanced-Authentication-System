package com.pnm.auth.dto.response;

import com.pnm.auth.domain.entity.UserOAuthProvider;
import com.pnm.auth.domain.enums.AuthProviderType;
import lombok.*;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserAuthProviderAdminResponse {

    private AuthProviderType providerType;
    private String providerId;
    private LocalDateTime linkedAt;

    public static UserAuthProviderAdminResponse fromEntity(UserOAuthProvider p) {
        return UserAuthProviderAdminResponse.builder()
                .providerType(p.getProviderType())
                .providerId(p.getProviderId())
                .linkedAt(p.getLinkedAt())
                .build();
    }
}


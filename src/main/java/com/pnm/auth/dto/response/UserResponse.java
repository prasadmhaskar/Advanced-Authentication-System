package com.pnm.auth.dto.response;

import com.pnm.auth.domain.entity.User;
import lombok.*;

import java.util.List;

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserResponse {

    private Long id;
    private String fullName;
    private String email;
    private List<String> roles;
    private boolean emailVerified;
    private boolean mfaEnabled;

    public static UserResponse from(User user) {
        return UserResponse.builder()
                .id(user.getId())
                .fullName(user.getFullName())
                .email(user.getEmail())
                .roles(user.getRoles())
                .emailVerified(user.getEmailVerified())
                .mfaEnabled(user.isMfaEnabled())
                .build();
    }
}


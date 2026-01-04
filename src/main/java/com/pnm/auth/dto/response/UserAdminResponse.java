package com.pnm.auth.dto.response;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.datatype.jsr310.deser.LocalDateTimeDeserializer;
import com.fasterxml.jackson.datatype.jsr310.ser.LocalDateTimeSerializer;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthProviderType;
import lombok.*;

import java.time.LocalDateTime;
import java.util.ArrayList; // ✅ Import this
import java.util.List;
import java.util.stream.Collectors;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserAdminResponse {
    private Long id;
    private String fullName;
    private String email;
    private List<String> roles;
    private boolean active;
    private boolean emailVerified;
    private boolean mfaEnabled;

    @JsonSerialize(using = LocalDateTimeSerializer.class)
    @JsonDeserialize(using = LocalDateTimeDeserializer.class)
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime createdAt;

    @JsonSerialize(using = LocalDateTimeSerializer.class)
    @JsonDeserialize(using = LocalDateTimeDeserializer.class)
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime updatedAt;

    private List<AuthProviderType> providers;

    public static UserAdminResponse from(User user) {
        return UserAdminResponse.builder()
                .id(user.getId())
                .fullName(user.getFullName())
                .email(user.getEmail())

                // 🚨 CRITICAL FIX: Wrap in new ArrayList to force standard Java List
                // This strips the Hibernate Proxy so Redis can serialize/deserialize it safely.
                .roles(user.getRoles() != null ? new ArrayList<>(user.getRoles()) : new ArrayList<>())

                .active(user.isActive())
                .emailVerified(user.getEmailVerified())
                .mfaEnabled(user.isMfaEnabled())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .providers(user.getAuthProviders() == null ? List.of() :
                        user.getAuthProviders().stream()
                                .map(p -> p.getProviderType())
                                .collect(Collectors.toList()))
                .build();
    }
}
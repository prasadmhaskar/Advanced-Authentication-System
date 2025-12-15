package com.pnm.auth.dto.response;

import com.pnm.auth.domain.entity.LoginActivity;
import lombok.*;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginActivityResponse {
    private Long id;
    private String email;
    private String ipAddress;
    private String userAgent;
    private String status;
    private String message;
    private LocalDateTime createdAt;

    public static LoginActivityResponse fromEntity(LoginActivity activity) {
        return LoginActivityResponse.builder()

                .id(activity.getId())
                .email(activity.getEmail())
                .ipAddress(activity.getIpAddress())
                .userAgent(activity.getUserAgent())
                .status(activity.getStatus())
                .message(activity.getMessage())
                .createdAt(activity.getCreatedAt())
                .build();

    }
}

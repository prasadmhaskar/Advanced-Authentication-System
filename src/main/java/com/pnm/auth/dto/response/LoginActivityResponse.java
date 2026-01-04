package com.pnm.auth.dto.response;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.datatype.jsr310.deser.LocalDateTimeDeserializer;
import com.fasterxml.jackson.datatype.jsr310.ser.LocalDateTimeSerializer;
import com.pnm.auth.domain.entity.LoginActivity;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor  // ✅ Required for Redis/Jackson deserialization
@AllArgsConstructor
public class LoginActivityResponse {

    private Long id;
    private String email;
    private String ipAddress;
    private String userAgent;
    private String status;     // Matches Entity "status"
    private String message;    // Matches Entity "message"

    @JsonSerialize(using = LocalDateTimeSerializer.class)
    @JsonDeserialize(using = LocalDateTimeDeserializer.class)
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
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
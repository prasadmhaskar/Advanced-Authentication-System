package com.pnm.auth.dto.response;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.datatype.jsr310.deser.LocalDateTimeDeserializer;
import com.fasterxml.jackson.datatype.jsr310.ser.LocalDateTimeSerializer;
import com.pnm.auth.domain.entity.UserActivity;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserActivityResponse {

    private Long id;
    private Long userId;
    private String email;
    private String ipAddress;
    private String userAgent;
    private String status;
    private String message;

    @JsonSerialize(using = LocalDateTimeSerializer.class)
    @JsonDeserialize(using = LocalDateTimeDeserializer.class)
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime createdAt;

    public static UserActivityResponse fromEntity(UserActivity activity) {
        return UserActivityResponse.builder()
                .id(activity.getId())
                .userId(activity.getUserId())
                .email(activity.getEmail())
                .ipAddress(activity.getIpAddress())
                .userAgent(activity.getUserAgent())
                .status(activity.getStatus())
                .message(activity.getMessage())
                .createdAt(activity.getCreatedAt())
                .build();
    }
}
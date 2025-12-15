package com.pnm.auth.dto.response;

import com.pnm.auth.domain.entity.UserIpLog;
import lombok.*;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserIpLogResponse {

    private Long id;
    private Long userId;
    private String ipAddress;
    private String userAgent;
    private LocalDateTime loginTime;
    private Boolean isSuspicious;

    private String countryCode;
    private String city;
    private Integer riskScore;
    private String riskReason;

    private String deviceSignature;
    private String deviceType;
    private String deviceName;


    public static UserIpLogResponse fromEntity(UserIpLog entity) {
        return UserIpLogResponse.builder()
                .id(entity.getId())
                .userId(entity.getUserId())
                .ipAddress(entity.getIpAddress())
                .userAgent(entity.getUserAgent())
                .loginTime(entity.getLoginTime())
                .isSuspicious(entity.getIsSuspicious())
                .countryCode(entity.getCountryCode())
                .city(entity.getCity())
                .riskScore(entity.getRiskScore())
                .riskReason(entity.getRiskReason())
                .deviceSignature(entity.getDeviceSignature())
                .deviceType(entity.getDeviceType())
                .deviceName(entity.getDeviceName())
                .build();
    }

}



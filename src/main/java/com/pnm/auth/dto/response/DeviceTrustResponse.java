package com.pnm.auth.dto.response;

import com.pnm.auth.domain.entity.TrustedDevice;
import lombok.*;

import java.time.LocalDateTime;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class DeviceTrustResponse {

    private Long id;
    private Long userId;
    private String deviceName;
    private String deviceSignature;
    private LocalDateTime trustedAt;
    private Boolean active;

    public static DeviceTrustResponse fromEntity(TrustedDevice device) {
        return DeviceTrustResponse.builder()
                .id(device.getId())
                .userId(device.getUserId())
                .deviceName(device.getDeviceName())
                .deviceSignature(device.getDeviceSignature())
                .trustedAt(device.getTrustedAt())
                .active(device.getActive())
                .build();
    }
}


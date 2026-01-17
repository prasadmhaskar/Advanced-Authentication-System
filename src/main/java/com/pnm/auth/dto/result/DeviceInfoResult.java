package com.pnm.auth.dto.result;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DeviceInfoResult {
    private String browser;
    private String os;
    private String deviceType;
    private String deviceName;
    private String signature;
}
package com.pnm.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DeviceInfo {
    private String browser;        // Chrome, Edge, Safari, Firefox, Other
    private String os;             // Windows, Mac, Linux, Android, iOS, Other
    private String deviceType;     // DESKTOP, MOBILE, TABLET, BOT, UNKNOWN
    private String deviceName;     // "Chrome on Windows", "Mobile Chrome on Android", etc.
    private String signature;      // "Chrome_Windows_DESKTOP", used for identification
}
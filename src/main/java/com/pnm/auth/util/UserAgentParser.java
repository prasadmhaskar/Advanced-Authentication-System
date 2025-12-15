package com.pnm.auth.util;

import com.pnm.auth.dto.result.DeviceInfoResult;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class UserAgentParser {

    private UserAgentParser() {
    }

    public static DeviceInfoResult parse(String userAgentRaw) {
        if (userAgentRaw == null || userAgentRaw.isBlank()) {
            return DeviceInfoResult.builder()
                    .browser("Unknown")
                    .os("Unknown")
                    .deviceType("UNKNOWN")
                    .deviceName("Unknown Device")
                    .signature("UNKNOWN")
                    .build();
        }

        String ua = userAgentRaw.toLowerCase();

        String browser = detectBrowser(ua);
        String os = detectOs(ua);
        String deviceType = detectDeviceType(ua);
        String deviceName = buildDeviceName(browser, os, deviceType);
        String signature = browser + "_" + os + "_" + deviceType;

        return DeviceInfoResult.builder()
                .browser(browser)
                .os(os)
                .deviceType(deviceType)
                .deviceName(deviceName)
                .signature(signature)
                .build();
    }

    private static String detectBrowser(String ua) {
        if (ua.contains("chrome") && !ua.contains("edg")) {
            return "Chrome";
        }
        if (ua.contains("edg")) {
            return "Edge";
        }
        if (ua.contains("firefox")) {
            return "Firefox";
        }
        if (ua.contains("safari") && !ua.contains("chrome")) {
            return "Safari";
        }
        if (ua.contains("opera") || ua.contains("opr")) {
            return "Opera";
        }
        if (ua.contains("headless") || ua.contains("phantomjs")) {
            return "Headless";
        }
        return "Other";
    }

    private static String detectOs(String ua) {
        if (ua.contains("windows")) return "Windows";
        if (ua.contains("mac os") || ua.contains("macintosh")) return "MacOS";
        if (ua.contains("x11") || ua.contains("linux")) return "Linux";
        if (ua.contains("android")) return "Android";
        if (ua.contains("iphone") || ua.contains("ipad") || ua.contains("ios")) return "iOS";
        return "Other";
    }

    private static String detectDeviceType(String ua) {
        if (ua.contains("mobi") || ua.contains("android")) {
            return "MOBILE";
        }
        if (ua.contains("tablet") || ua.contains("ipad")) {
            return "TABLET";
        }
        if (ua.contains("headless") || ua.contains("phantomjs") || ua.contains("selenium")) {
            return "BOT";
        }
        return "DESKTOP";
    }

    private static String buildDeviceName(String browser, String os, String deviceType) {
        return switch (deviceType) {
            case "MOBILE" -> "Mobile " + browser + " on " + os;
            case "TABLET" -> "Tablet " + browser + " on " + os;
            case "BOT" -> "Bot/" + browser + " on " + os;
            default -> browser + " on " + os;
        };
    }
}

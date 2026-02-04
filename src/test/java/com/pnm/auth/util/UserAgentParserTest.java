package com.pnm.auth.util;

import com.pnm.auth.dto.result.DeviceInfoResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class UserAgentParserTest {

    @Test
    @DisplayName("Returns unknown values when user agent is null or blank")
    void parse_ReturnsUnknownWhenNullOrBlank() {
        DeviceInfoResult nullResult = UserAgentParser.parse(null);
        DeviceInfoResult blankResult = UserAgentParser.parse("   ");

        assertUnknownResult(nullResult);
        assertUnknownResult(blankResult);
    }

    @Test
    @DisplayName("Detects Chrome on Windows desktop and builds signature")
    void parse_DetectsChromeOnWindowsDesktop() {
        String userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                + "AppleWebKit/537.36 (KHTML, like Gecko) "
                + "Chrome/120.0.0.0 Safari/537.36";

        DeviceInfoResult result = UserAgentParser.parse(userAgent);

        assertEquals("Chrome", result.getBrowser());
        assertEquals("Windows", result.getOs());
        assertEquals("DESKTOP", result.getDeviceType());
        assertEquals("Chrome on Windows", result.getDeviceName());
        assertEquals("Chrome_Windows_DESKTOP", result.getSignature());
    }

    @Test
    @DisplayName("Detects Chrome on Windows desktop and builds signature")
    void parse_DetectsEdgeOnWindowsDesktop() {
        String userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0";

        DeviceInfoResult result = UserAgentParser.parse(userAgent);

        assertEquals("Edge", result.getBrowser());
        assertEquals("Windows", result.getOs());
        assertEquals("DESKTOP", result.getDeviceType());
        assertEquals("Edge on Windows", result.getDeviceName());
        assertEquals("Edge_Windows_DESKTOP", result.getSignature());
    }

    @Test
    @DisplayName("Detects Safari on iPhone as mobile")
    void parse_DetectsSafariOnIphone() {
        String userAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like) "
                + "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1";

        DeviceInfoResult result = UserAgentParser.parse(userAgent);

        assertEquals("Safari", result.getBrowser());
        assertEquals("iOS", result.getOs());
        assertEquals("MOBILE", result.getDeviceType());
        assertEquals("Mobile Safari on iOS", result.getDeviceName());
        assertEquals("Safari_iOS_MOBILE", result.getSignature());
    }

    @Test
    @DisplayName("Detects headless browser as bot")
    void parse_DetectsHeadlessBot() {
        String userAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                + "(KHTML, like Gecko) HeadlessChrome/114.0.0.0 Safari/537.36";

        DeviceInfoResult result = UserAgentParser.parse(userAgent);

        assertEquals("Headless", result.getBrowser(), "Browser should be detected as Headless");
        assertEquals("Linux", result.getOs());
        assertEquals("BOT", result.getDeviceType());
        assertEquals("Bot/Headless on Linux", result.getDeviceName());
        assertEquals("Headless_Linux_BOT", result.getSignature());
    }

    private void assertUnknownResult(DeviceInfoResult result) {
        assertNotNull(result);
        assertEquals("Unknown", result.getBrowser());
        assertEquals("Unknown", result.getOs());
        assertEquals("UNKNOWN", result.getDeviceType());
        assertEquals("Unknown Device", result.getDeviceName());
        assertEquals("UNKNOWN", result.getSignature());
    }
}


package com.pnm.auth.util;

import jakarta.servlet.http.HttpServletRequest;
import java.net.InetAddress;

public final class IpUtils {

    private IpUtils() {
        throw new UnsupportedOperationException("Utility class cannot be instantiated");
    }

    public static String getClientIp(HttpServletRequest request) {
        return request.getRemoteAddr();
    }

    public static boolean isPrivateIp(String ip) {
        try {
            InetAddress inet = InetAddress.getByName(ip);
            return inet.isSiteLocalAddress() ||
                    inet.isAnyLocalAddress() ||
                    inet.isLoopbackAddress() ||
                    inet.isLinkLocalAddress();
        } catch (Exception e) {
            return false;
        }
    }
}
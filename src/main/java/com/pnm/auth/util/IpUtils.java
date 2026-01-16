package com.pnm.auth.util;

import jakarta.servlet.http.HttpServletRequest;
import java.net.InetAddress;

public final class IpUtils {

    private IpUtils() {
        throw new UnsupportedOperationException("Utility class cannot be instantiated");
    }

    public static String getClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");

        if (xff != null && !xff.isEmpty() && !"unknown".equalsIgnoreCase(xff)) {
            // Take only the first IP in the chain (the original client)
            String ip = xff.split(",")[0].trim();

            if (isValidIp(ip)) {
                return ip;
            }
        }

        // Fallback to the direct connection IP
        return request.getRemoteAddr();
    }

    private static boolean isValidIp(String ip) {
        // Basic length check for IPv4/IPv6 sanity
        return ip != null && ip.length() <= 45;
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
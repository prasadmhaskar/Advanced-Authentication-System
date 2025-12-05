package com.pnm.auth.util;

import java.net.InetAddress;

public class IpUtils {

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


package com.pnm.auth.util;

public class MaskingUtil {
    public static String maskEmail(String email) {
        if (email == null || email.isEmpty()) return "UNKNOWN";
        int atIndex = email.indexOf('@');
        if (atIndex <= 1) return "****" + email.substring(atIndex);
        return email.charAt(0) + "***" + email.substring(atIndex - 1);
    }
}

package com.pnm.auth.util;

public final class MaskingUtil {

    private MaskingUtil() {
        throw new UnsupportedOperationException("Utility class cannot be instantiated");
    }

    public static String maskEmail(String email) {
        if (email == null || email.isEmpty()) return "UNKNOWN";
        int atIndex = email.indexOf('@');
        if (atIndex <= 1) return "****" + email.substring(atIndex);
        return email.charAt(0) + "***" + email.substring(atIndex - 1);
    }
}

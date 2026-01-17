package com.pnm.auth.util;

import com.pnm.auth.service.impl.user.UserDetailsImpl;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException; // <--- Specific Exception
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public final class AuthUtil {

    // Private constructor to prevent instantiation
    private AuthUtil() {
        throw new IllegalStateException("Utility class cannot be instantiated");
    }

    public static Long getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !(authentication.getPrincipal() instanceof UserDetailsImpl userDetails)) {
            throw new AuthenticationCredentialsNotFoundException("User not authenticated");
        }

        return userDetails.getId();
    }

    public static String getCurrentEmail() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !(authentication.getPrincipal() instanceof UserDetailsImpl userDetails)) {
            throw new AuthenticationCredentialsNotFoundException("User not authenticated");
        }

        return userDetails.getEmail();
    }
}
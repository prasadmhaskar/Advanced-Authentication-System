package com.pnm.auth.security.filter;


import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@Slf4j
@Order(Ordered.HIGHEST_PRECEDENCE + 10)  // Run early but after RequestLoggingFilter
public class SecurityHeadersFilter extends OncePerRequestFilter {

    // Adjust for frontend domain when React app is added
    private static final String FRONTEND_DOMAIN = "http://localhost:5173"; // Vite/React dev
    private static final String FRONTEND_PROD = "https://yourfrontend.com";

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();

        applyCommonHeaders(response);

        applyReferrerPolicy(response);

        applyPermissionsPolicy(response);

        applyCORSafeHeaders(response);

        applyContentSecurityPolicy(
                response,
                path
        );

        log.trace("SecurityHeadersFilter applied for path={}", path);

        filterChain.doFilter(request, response);
    }

    // ============================================================
    // HIGH-SECURITY HEADERS (ALL REQUESTS)
    // ============================================================

    private void applyCommonHeaders(HttpServletResponse response) {
        response.setHeader("X-Frame-Options", "DENY"); // Prevent clickjacking
        response.setHeader("X-Content-Type-Options", "nosniff"); // Prevent MIME sniffing
        response.setHeader("X-XSS-Protection", "1; mode=block"); // Browser XSS filter
        response.setHeader("X-Permitted-Cross-Domain-Policies", "none"); // Block Flash exploits
    }

    private void applyReferrerPolicy(HttpServletResponse response) {
        response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    }

    private void applyPermissionsPolicy(HttpServletResponse response) {
        // Disable access to sensitive APIs unless explicitly needed
        response.setHeader("Permissions-Policy",
                "camera=(), microphone=(), geolocation=(), payment=(), usb=(), autoplay=()");
    }

    private void applyCORSafeHeaders(HttpServletResponse response) {
        response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
        response.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
        response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    }

    // ============================================================
    // CONTENT SECURITY POLICY (DYNAMIC BASED ON PATH)
    // ============================================================

    private void applyContentSecurityPolicy(HttpServletResponse response, String path) {

        // OAuth callbacks require relaxed CSP
        if (path.startsWith("/login/oauth2") || path.startsWith("/oauth2")) {
            response.setHeader("Content-Security-Policy",
                    "default-src 'self'; script-src 'self' 'unsafe-inline'; connect-src 'self';");
            return;
        }

        // ADMIN paths require stricter CSP
        if (path.startsWith("/api/admin")) {
            response.setHeader("Content-Security-Policy",
                    "default-src 'none'; " +
                            "script-src 'self'; " +
                            "connect-src 'self'; " +
                            "img-src 'self'; " +
                            "style-src 'self'; " +
                            "object-src 'none';");
            return;
        }

        // FUTURE: React frontend integration
        // This CSP allows:
        // - React dev server (localhost:5173)
        // - Production frontend domain
        // - API calls to backend
        response.setHeader("Content-Security-Policy",
                "default-src 'self'; " +
                        "script-src 'self' 'unsafe-inline' " + FRONTEND_DOMAIN + " " + FRONTEND_PROD + "; " +
                        "style-src 'self' 'unsafe-inline'; " +
                        "img-src 'self' data:; " +
                        "font-src 'self'; " +
                        "connect-src 'self' " + FRONTEND_DOMAIN + " " + FRONTEND_PROD + "; " +
                        "object-src 'none';");
    }
}


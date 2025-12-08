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
@Order(Ordered.HIGHEST_PRECEDENCE + 10) // Runs early but after RequestLoggingFilter
public class SecurityHeadersFilter extends OncePerRequestFilter {

    // TODO: Replace with actual frontend domain during deployment
    private static final String FRONTEND_DEV = "http://localhost:5173";
    private static final String FRONTEND_PROD = "https://yourfrontend.com";

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();

        applyCommonSecurityHeaders(response);
        applyCorsRelatedSecurityHeaders(response);
        applyReferrerPolicy(response);
        applyPermissionsPolicy(response);

        applyContentSecurityPolicy(response, path);

        log.trace("SecurityHeadersFilter applied for path={}", path);

        filterChain.doFilter(request, response);
    }

    // --------------------------------------------------------------
    // 1. CORE SECURITY HEADERS (MUST APPLY TO ALL ROUTES)
    // --------------------------------------------------------------

    private void applyCommonSecurityHeaders(HttpServletResponse response) {
        response.setHeader("X-Frame-Options", "DENY");                      // Prevent clickjacking
        response.setHeader("X-Content-Type-Options", "nosniff");            // Disable MIME sniffing
        response.setHeader("X-XSS-Protection", "1; mode=block");            // Legacy XSS protection
        response.setHeader("X-Permitted-Cross-Domain-Policies", "none");    // Block Adobe/Flash exploits
    }

    private void applyReferrerPolicy(HttpServletResponse response) {
        response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    }

    private void applyPermissionsPolicy(HttpServletResponse response) {
        response.setHeader("Permissions-Policy",
                "camera=(), microphone=(), geolocation=(), payment=(), usb=(), autoplay=(), fullscreen=()");
    }

    private void applyCorsRelatedSecurityHeaders(HttpServletResponse response) {
        response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
        response.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
        response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    }

    // --------------------------------------------------------------
    // 2. CONTENT SECURITY POLICY (DYNAMIC BASED ON PATH)
    // --------------------------------------------------------------

    private void applyContentSecurityPolicy(HttpServletResponse response, String path) {

        // RELAXED CSP FOR OAUTH REDIRECT HANDSHAKES
        if (path.startsWith("/login/oauth2") || path.startsWith("/oauth2")) {
            response.setHeader("Content-Security-Policy",
                    "default-src 'self'; " +
                            "script-src 'self' 'unsafe-inline'; " +       // OAuth libs often inline scripts
                            "connect-src 'self'; " +
                            "style-src 'self' 'unsafe-inline';");
            return;
        }

        // HIGHLY RESTRICTED ADMIN PANEL
        if (path.startsWith("/api/admin")) {
            response.setHeader("Content-Security-Policy",
                    "default-src 'none'; " +
                            "script-src 'self'; " +
                            "img-src 'self'; " +
                            "style-src 'self'; " +
                            "connect-src 'self'; " +
                            "font-src 'self'; " +
                            "object-src 'none';");
            return;
        }

        // FUTURE FRONTEND INTEGRATION (React)
        response.setHeader("Content-Security-Policy",
                "default-src 'self'; " +
                        "script-src 'self' 'unsafe-inline' " + FRONTEND_DEV + " " + FRONTEND_PROD + "; " +
                        "style-src 'self' 'unsafe-inline'; " +
                        "img-src 'self' data:; " +
                        "font-src 'self'; " +
                        "connect-src 'self' " + FRONTEND_DEV + " " + FRONTEND_PROD + "; " +
                        "object-src 'none';");
    }
}

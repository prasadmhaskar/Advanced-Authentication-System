package com.pnm.auth.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pnm.auth.dto.response.ApiResponse;
import com.pnm.auth.service.impl.redis.RedisRateLimiterServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@Slf4j
public class RedisRateLimiterFilter extends OncePerRequestFilter {

    private final RedisRateLimiterServiceImpl rateLimiterService;

    public RedisRateLimiterFilter(RedisRateLimiterServiceImpl rateLimiterService) {
        this.rateLimiterService = rateLimiterService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // 1️⃣ GLOBAL PROTECTION: Never skip.
        // We want to rate limit EVERY request to the API.
        // Only skip static resources or health checks if necessary.
        String path = request.getRequestURI();

        return path.startsWith("/actuator") ||
                path.startsWith("/favicon.ico") ||
                path.startsWith("/v3/api-docs") || path.startsWith("/swagger-ui");
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String path = request.getRequestURI();
        String ip = request.getRemoteAddr();

        String rateLimitKey;
        int maxRequests;
        int windowSeconds;

        // 2️⃣ DYNAMIC RULES based on Endpoint Sensitivity

        // A) CRITICAL AUTH ENDPOINTS (Strict: 5 req / min)
        // Login, Register, Forgot Password
        if (path.startsWith("/api/auth")) {
            rateLimitKey = "AUTH:" + ip + ":" + path;
            maxRequests = 5;
            windowSeconds = 60;
        }
        // B) SENSITIVE ADMIN ACTIONS (Strict: 10 req / min)
        else if (path.startsWith("/api/admin")) {
            rateLimitKey = "ADMIN:" + ip + ":" + path;
            maxRequests = 10;
            windowSeconds = 60;
        }
        // C) GENERAL API (Loose: 100 req / min)
        // Normal user browsing, fetching profile, etc.
        else {
            rateLimitKey = "GENERAL:" + ip; // Shared bucket for all general actions
            maxRequests = 100;
            windowSeconds = 60;
        }

        // 🔐 Special MFA Handling Override
        if (path.startsWith("/api/auth/mfa/resend")) {
            String tokenId = request.getParameter("otpTokenId");
            String email = request.getParameter("email");
            String userKey = tokenId != null ? tokenId : email;

            if (userKey != null) {
                rateLimitKey = "MFA_RESEND:" + userKey;
                maxRequests = 3;
                windowSeconds = 300; // 5 minutes
            }
        }

        // 3️⃣ EXECUTE CHECK
        boolean allowed = rateLimiterService.isAllowed(rateLimitKey, maxRequests, windowSeconds);

        if (!allowed) {
            log.warn("RateLimiter: BLOCKED key={} path={}", rateLimitKey, path);
            response.setStatus(429);
            response.setContentType("application/json");
            // ... (Write your ApiResponse JSON here) ...
            return;
        }

        filterChain.doFilter(request, response);
    }
}


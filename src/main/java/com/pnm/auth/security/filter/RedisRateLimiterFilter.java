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
        String path = request.getRequestURI();

        return !(
                path.startsWith("/api/auth/login") ||
                        path.startsWith("/api/auth/register") ||
                        path.startsWith("/api/auth/forgot-password") ||
                        path.startsWith("/api/auth/refresh") ||
                        path.startsWith("/api/auth/verify") ||
                        path.startsWith("/api/auth/otp/resend")
        );
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

        // 🔐 Special handling for MFA resend
        if (path.startsWith("/api/auth/mfa/resend")) {

            // Prefer tokenId (best), fallback to email
            String tokenId = request.getParameter("otpTokenId");
            String email = request.getParameter("email");

            String userKey = tokenId != null ? tokenId : email;

            if (userKey == null) {
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                response.getWriter().write("Missing otpTokenId or email");
                return;
            }

            rateLimitKey = "MFA_RESEND:" + userKey + ":" + ip;
            maxRequests = 3;      // 🔒 strict
            windowSeconds = 300;  // 5 minutes

        } else {
            // Default auth rate limit
            rateLimitKey = "AUTH:" + ip + ":" + path;
            maxRequests = 5;
            windowSeconds = 60;
        }

        boolean allowed = rateLimiterService.isAllowed(
                rateLimitKey,
                maxRequests,
                windowSeconds
        );

        if (!allowed) {
            log.warn("RateLimiter: BLOCKED key={} path={}", rateLimitKey, path);

            ApiResponse<Void> body = ApiResponse.error(
                    "RATE_LIMIT_EXCEEDED",
                    "Too many requests. Please try again later.",
                    path
            );

            response.setStatus(429);
            response.setContentType("application/json");
            response.getWriter().write(new ObjectMapper().writeValueAsString(body));
            return;
        }

        filterChain.doFilter(request, response);
    }

}


package com.pnm.auth.security.filter;

import com.pnm.auth.exception.custom.RateLimitExceededException;
import com.pnm.auth.service.impl.redis.RedisRateLimiterServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;

@Component
@Slf4j
public class RedisRateLimiterFilter extends OncePerRequestFilter {

    private final RedisRateLimiterServiceImpl rateLimiterService;
    private final HandlerExceptionResolver exceptionResolver;

    // INJECT THE RESOLVER
    public RedisRateLimiterFilter(
            RedisRateLimiterServiceImpl rateLimiterService,
            @Qualifier("handlerExceptionResolver") HandlerExceptionResolver exceptionResolver
    ) {
        this.rateLimiterService = rateLimiterService;
        this.exceptionResolver = exceptionResolver;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
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

        // Special MFA Handling Override
        if (path.startsWith("/api/auth/mfa/resend")) {
            String tokenId = request.getParameter("otpTokenId");
            String email = request.getParameter("email");
            String userKey = tokenId != null ? tokenId : email;

            if (userKey != null) {
                rateLimitKey = "MFA_RESEND:" + userKey;
                maxRequests = 3;
                windowSeconds = 300;
            }
        }

        boolean allowed = rateLimiterService.isAllowed(rateLimitKey, maxRequests, windowSeconds);

        if (!allowed) {
            log.warn("RateLimiter: BLOCKED key={} path={}", rateLimitKey, path);
//            response.setStatus(429);
//            response.setContentType("application/json");
//
//            String jsonResponse = "{\"status\": 429, \"error\": \"Too Many Requests\", \"message\": \"Rate limit exceeded. Try again later.\"}";
//
//            response.getWriter().write(jsonResponse);
//            return;

            // THIS IS THE FIX:
            // Instead of throwing, we ask Spring to handle the exception for us.
            exceptionResolver.resolveException(
                    request,
                    response,
                    null,
                    new RateLimitExceededException("You have exhausted your API request quota. Please wait a moment.")
            );
            return;
        }

        filterChain.doFilter(request, response);
    }
}


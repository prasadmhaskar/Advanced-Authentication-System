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
                        path.startsWith("/api/auth/verify")
        );
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String ip = request.getRemoteAddr();
        String key = ip + ":" + request.getRequestURI();

        boolean allowed = rateLimiterService.isAllowed(key, 5, 60);

        if (!allowed) {
            log.warn("RateLimiter: BLOCKED ip={} path={}", ip, request.getServletPath());

            ApiResponse<Void> body = ApiResponse.error(
                    "RATE_LIMIT_EXCEEDED",
                    "Too many requests. Try again later.",
                    request.getRequestURI()
            );

            response.setStatus(429);
            response.setContentType("application/json");
            response.getWriter().write(new ObjectMapper().writeValueAsString(body));
            return;
        }

        filterChain.doFilter(request, response);
    }
}


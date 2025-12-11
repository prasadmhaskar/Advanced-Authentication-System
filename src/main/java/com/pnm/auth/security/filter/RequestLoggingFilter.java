package com.pnm.auth.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.jboss.logging.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;
import java.util.UUID;

@Component
@Slf4j
public class RequestLoggingFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String requestId = Optional.ofNullable(request.getHeader("X-Request-Id"))
                .filter(h -> !h.isBlank())
                .orElse(UUID.randomUUID().toString());
        String ip = getClientIp(request);
        String userAgent = request.getHeader("User-Agent");
        String path = request.getRequestURI();
        String method = request.getMethod();



        MDC.put("requestId", requestId);
        MDC.put("ip", ip);
        MDC.put("userAgent", userAgent != null ? userAgent : "unknown");
        MDC.put("path", path);
        MDC.put("method", method);

        log.info("REQUEST_START");

        try {
            filterChain.doFilter(request, response);
        } finally {
            log.info("REQUEST_END status={}", response.getStatus());
            response.setHeader("X-Request-Id", requestId);
            MDC.clear();
        }
    }

    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null) ip = request.getRemoteAddr();
        return ip;
    }
}


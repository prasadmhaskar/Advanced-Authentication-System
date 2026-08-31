package com.pnm.auth.security.filter;

import com.pnm.auth.util.IpUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
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

        long startTime = System.currentTimeMillis();

        String requestId = Optional.ofNullable(request.getHeader("X-Request-Id"))
                .filter(h -> !h.isBlank())
                .orElse(UUID.randomUUID().toString());

        String ip = IpUtils.getClientIp(request);
        String userAgent = Optional.ofNullable(request.getHeader("User-Agent")).orElse("unknown");

        String path = request.getRequestURI();
        String method = request.getMethod();

        MDC.put("requestId", requestId);
        MDC.put("ip", ip);
        MDC.put("userAgent", userAgent);
        MDC.put("path", path);
        MDC.put("method", method);

        log.info("request_start");

        try {
            filterChain.doFilter(request, response);
        } finally {
            long duration = System.currentTimeMillis() - startTime;

            String status = String.valueOf(response.getStatus());
            String durationMs = String.valueOf(duration);

            log.info("request_end [Status:{}] [Duration:{} ms]", status, durationMs);

            response.setHeader("X-Request-Id", requestId);
            MDC.clear();
        }
    }

}


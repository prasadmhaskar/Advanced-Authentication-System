package com.pnm.auth.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
@Slf4j
public class    RateLimiterFilter extends OncePerRequestFilter {

    private static class Counter {
        int count = 0;
        long timestamp = System.currentTimeMillis();
    }

    private final Map<String, Counter> store = new ConcurrentHashMap<>();

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {

        String path = request.getServletPath();
        boolean filter = (path.startsWith("/api/auth/login") ||
                path.startsWith("/api/auth/register") ||
                path.startsWith("/api/auth/forgot-password") ||
                path.startsWith("/api/auth/verify") ||
                path.startsWith("/api/auth/refresh"));

        if (filter) {
            log.debug("RateLimiterFilter: Filtering enabled for path={}", path);
        } else {
            log.debug("RateLimiterFilter: Skipping rate limit filter for path={}", path);
        }

        return !filter; // return true = skip filter
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String ip = request.getRemoteAddr();

        Counter counter = store.computeIfAbsent(ip, k -> {
            log.info("RateLimiterFilter: New IP detected -> {}", k);
            return new Counter();
        });

        long now = System.currentTimeMillis();
        long elapsed = now - counter.timestamp;

        // Reset window
        if (elapsed > 60_000) {
            log.info("RateLimiterFilter: Resetting counter for IP={} after {} ms", ip, elapsed);
            counter.count = 0;
            counter.timestamp = now;
        }

        // Check limit
        if (counter.count >= 5) {
            log.warn("RateLimiterFilter: RATE LIMIT EXCEEDED for IP={} | count={}", ip, counter.count);
            response.setStatus(429);
            response.getWriter().write("Too many requests. Try again later.");
            return;
        }

        counter.count++;
        log.info("RateLimiterFilter: Request allowed for IP={} | count={}", ip, counter.count);

        filterChain.doFilter(request, response);
    }
}

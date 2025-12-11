package com.pnm.auth.security.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Set;

@Component
@Slf4j
@Order(Ordered.HIGHEST_PRECEDENCE + 5)
public class BlockHttpMethodsFilter extends OncePerRequestFilter {

    private static final Set<String> BLOCKED = Set.of("TRACE", "TRACK");

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String method = request.getMethod();
        if (BLOCKED.contains(method)) {
            log.warn("Blocked HTTP method {} for path={}", method, request.getRequestURI());
            response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method not allowed");
            return;
        }

        filterChain.doFilter(request, response);
    }
}

package com.pnm.auth.web.filter;

import com.pnm.auth.web.context.RequestContext;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class RequestContextFilter extends OncePerRequestFilter {

    public static final String REQUEST_CONTEXT_ATTR = "REQUEST_CONTEXT";

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isBlank()) {
            ip = request.getRemoteAddr();
        }

        String userAgent = request.getHeader("User-Agent");
        String path = request.getRequestURI();

        RequestContext context = new RequestContext(ip, userAgent, path);

        request.setAttribute(REQUEST_CONTEXT_ATTR, context);

        filterChain.doFilter(request, response);
    }
}

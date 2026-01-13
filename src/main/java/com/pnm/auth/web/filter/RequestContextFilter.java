package com.pnm.auth.web.filter;

import com.pnm.auth.util.IpUtils;
import com.pnm.auth.web.context.RequestContext;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class RequestContextFilter extends OncePerRequestFilter {

    public static final String REQUEST_CONTEXT_ATTR = "REQUEST_CONTEXT";
    private static final String MDC_IP_KEY = "clientIp";
    private static final String MDC_UA_KEY = "userAgent";

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String ip = IpUtils.getClientIp(request);
        String userAgent = request.getHeader("User-Agent");
        String path = request.getRequestURI();

        RequestContext context = new RequestContext(ip, userAgent, path);
        request.setAttribute(REQUEST_CONTEXT_ATTR, context);

        MDC.put(MDC_IP_KEY, ip);
        MDC.put(MDC_UA_KEY, userAgent);

        try {
            filterChain.doFilter(request, response);
        }
        finally {
            MDC.clear();
        }
    }
}

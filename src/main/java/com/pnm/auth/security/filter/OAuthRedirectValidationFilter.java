package com.pnm.auth.security.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Component
@Slf4j
@Order(Ordered.HIGHEST_PRECEDENCE + 7)
public class OAuthRedirectValidationFilter extends OncePerRequestFilter {

    private final List<String> allowedRedirects;

    // ⭐ KEEP ONLY THIS CONSTRUCTOR
    public OAuthRedirectValidationFilter(
            @Value("${security.oauth.allowed-redirect-uris}") String allowed
    ) {
        if (StringUtils.hasText(allowed)) {
            allowedRedirects = Arrays.stream(allowed.split(","))
                    .map(String::trim)
                    .collect(Collectors.toList());
        } else {
            allowedRedirects = List.of();
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return !(path.startsWith("/oauth2/authorize")
                || path.startsWith("/login/oauth2")
                || path.startsWith("/oauth2/"));
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String redirectUri = request.getParameter("redirect_uri");

        if (redirectUri != null && !allowedRedirects.contains(redirectUri)) {
            log.warn("Rejected OAuth redirect_uri={} for path={}", redirectUri, request.getRequestURI());
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid redirect_uri");
            return;
        }

        filterChain.doFilter(request, response);
    }
}

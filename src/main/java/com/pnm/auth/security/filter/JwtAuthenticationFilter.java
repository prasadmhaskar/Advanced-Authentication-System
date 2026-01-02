package com.pnm.auth.security.filter;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.util.JwtUtil;
import com.pnm.auth.service.impl.user.UserDetailsImpl;
import com.pnm.auth.util.BlacklistedTokenStore;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final UserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final BlacklistedTokenStore blacklistedTokenStore;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        log.debug("JwtAuthenticationFilter.shouldNotFilter: Checking path={}", path);

        boolean skip = path.startsWith("/api/auth/login") ||
                path.startsWith("/api/auth/register") ||
                path.startsWith("/api/auth/verify") ||
                path.startsWith("/api/auth/verify/resend") ||
                path.startsWith("/api/auth/refresh") ||
                path.startsWith("/api/auth/forgot-password") ||
                path.startsWith("/api/auth/reset-password") ||
                path.startsWith("/api/auth/link-oauth") ||
                path.startsWith("/api/auth/setup-password") ||
                path.equals("/error") ||
                path.equals("/favicon.ico");

        if (skip) {
            log.info("JwtAuthenticationFilter: Skipping filter for path={}", path);
        }

        return skip;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        log.debug("JwtAuthenticationFilter: doFilterInternal started for URI={}", request.getRequestURI());

        String authHeader = request.getHeader("Authorization");
        String jwt = null;
        String username = null;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            jwt = authHeader.substring(7);
            log.debug("JwtAuthenticationFilter: Bearer token detected tokenPrefix={}", jwt.length() > 10 ? jwt.substring(0, 10) : jwt);

            try {
                username = jwtUtil.extractUsername(jwt);
                log.info("JwtAuthenticationFilter: Username extracted from token={}", username);
            } catch (Exception e) {
                log.warn("JwtAuthenticationFilter: Failed to extract username from token. Reason={}", e.getMessage());
            }
        } else {
            log.debug("JwtAuthenticationFilter: No valid Authorization header found");
        }

        // Authentication block
        if (username != null &&
                SecurityContextHolder.getContext().getAuthentication() == null) {

            log.info("JwtAuthenticationFilter: Loading userDetails for username={}", username);
            UserDetailsImpl userDetails = (UserDetailsImpl) userDetailsService.loadUserByUsername(username);

            User user = userRepository.findByEmail(username).orElse(null);
            if (user != null && !user.isActive()) {
                log.warn("Blocked user attempted JWT access: {}", username);
                filterChain.doFilter(request, response);
                return;
            }

            // ⭐ NEW: Check blacklisted token
            if (blacklistedTokenStore.isBlacklisted(jwt)) {
                log.warn("JwtAuthenticationFilter: Blocked JWT (blacklisted) tokenPrefix={}",
                        jwt.length() > 10 ? jwt.substring(0,10) : jwt);
                filterChain.doFilter(request, response);
                return;
            }

            if (!jwtUtil.isTokenExpired(jwt)) {
                log.info("JwtAuthenticationFilter: Token is valid. Authenticating user={}", username);

                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities()
                        );

                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                SecurityContextHolder.getContext().setAuthentication(authToken);
            } else {
                log.warn("JwtAuthenticationFilter: Token is expired for username={}", username);
            }
        }

        log.debug("JwtAuthenticationFilter: Continuing filter chain for URI={}", request.getRequestURI());
        filterChain.doFilter(request, response);
    }
}


package com.pnm.auth.security.filter;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.service.impl.user.UserDetailsImpl;
import com.pnm.auth.util.BlacklistedTokenStore;
import com.pnm.auth.util.JwtUtil;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final BlacklistedTokenStore blacklistedTokenStore;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");
        String jwt = null;
        String username = null;
        Claims claims = null;

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

            jwt = authHeader.substring(7);

            // Check redis for blacklisted token
            if (blacklistedTokenStore.isBlacklisted(jwt)) {
                log.warn("Rejected blacklisted token");
                filterChain.doFilter(request, response);
                return;
            }

            try {
                claims = jwtUtil.extractAllClaims(jwt);
                username = claims.getSubject();
            } catch (Exception e) {
                log.warn("Invalid JWT: {}", e.getMessage());
            }

        // Authentication block
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            User user = userRepository.findByEmail(username).orElse(null);

            if (user == null) {
                log.warn("JWT valid but user no longer exists: {}", username);
                filterChain.doFilter(request, response);
                return;
            }

            if (!user.isActive()) {
                log.warn("Blocked user attempted access: {}", username);
                filterChain.doFilter(request, response);
                return;
            }

            Integer tokenVersionInJwt = claims.get("tv", Integer.class);
            if (tokenVersionInJwt == null || !tokenVersionInJwt.equals(user.getTokenVersion())) {
                log.warn("Token version mismatch for user={}", user.getEmail());
                filterChain.doFilter(request, response);
                return;
            }

            if (!jwtUtil.isTokenExpired(jwt)) {

                UserDetailsImpl userDetails = new UserDetailsImpl(user);

                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities()
                        );

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
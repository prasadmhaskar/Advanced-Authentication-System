package com.pnm.auth.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pnm.auth.dto.response.ApiResponse;
import com.pnm.auth.security.filter.*;
import com.pnm.auth.security.oauth.OAuth2SuccessHandler;
import com.pnm.auth.service.impl.user.UserDetailsServiceImpl;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@Slf4j
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtFilter;
    private final UserDetailsServiceImpl userDetailsServiceImpl;
    private final OAuth2SuccessHandler oAuth2SuccessHandler;
    private final RedisRateLimiterFilter redisRateLimiterFilter;
    private final RequestLoggingFilter requestLoggingFilter;
    private final SecurityHeadersFilter securityHeadersFilter;
    private final ObjectMapper objectMapper;
    private final BlockHttpMethodsFilter blockHttpMethodsFilter;
    private final OAuthRedirectValidationFilter oauthRedirectValidationFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        log.info("SecurityConfig.securityFilterChain(): initializing");

        http
                // -----------------------------------------------------
                // CORS / CSRF / Stateless Sessions
                // -----------------------------------------------------
                .cors(cors -> {})
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // -----------------------------------------------------
                // Exception Handling (401 / 403)
                // -----------------------------------------------------
                .exceptionHandling(ex -> {
                    ex.authenticationEntryPoint(authenticationEntryPoint());
                    ex.accessDeniedHandler(accessDeniedHandler());
                })

                // -----------------------------------------------------
                // Authorization Rules
                // -----------------------------------------------------
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .requestMatchers("/api/user/**").hasAnyRole("USER", "ADMIN")
                        .requestMatchers(
                                "/api/auth/register",
                                "/api/auth/login",
                                "/api/auth/verify",
                                "/api/auth/verify/resend",
                                "/api/auth/refresh",
                                "/api/auth/forgot-password",
                                "/api/auth/setup-password",
                                "/oauth2/**",
                                "/login/oauth2/**"
                        ).permitAll()
                        .anyRequest().authenticated()
                )

                // -----------------------------------------------------
                // OAuth2 Login
                // -----------------------------------------------------
                .oauth2Login(oauth2 -> {
                    oauth2.successHandler(oAuth2SuccessHandler);
                    oauth2.failureHandler((request, response, ex) -> {
                        log.error("OAuth2 Login Failed: {}", ex.getMessage());
                        writeErrorResponse(
                                request, response,
                                HttpStatus.UNAUTHORIZED,
                                "OAUTH2_AUTH_FAILED",
                                "OAuth2 authentication failed"
                        );
                    });
                })

                // -----------------------------------------------------
                // UserDetails service for AuthenticationManager
                // -----------------------------------------------------
                .userDetailsService(userDetailsServiceImpl);

        // ---------------------------
// Register filters (correct order)
// ---------------------------

// 1) Register requestLoggingFilter first so it becomes a valid anchor
        http.addFilterBefore(requestLoggingFilter, UsernamePasswordAuthenticationFilter.class);

// 2) Now other filters can be added relative to RequestLoggingFilter
        http.addFilterBefore(blockHttpMethodsFilter, RequestLoggingFilter.class);
        http.addFilterBefore(oauthRedirectValidationFilter, RequestLoggingFilter.class);

// 3) Apply security headers after request logging
        http.addFilterAfter(securityHeadersFilter, RequestLoggingFilter.class);

// 4) Rate limiter (requires MDC from requestLoggingFilter)
        http.addFilterBefore(redisRateLimiterFilter, UsernamePasswordAuthenticationFilter.class);

// 5) JWT Authentication (before UsernamePasswordAuthenticationFilter)
        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        log.info("SecurityConfig.securityFilterChain(): final chain built successfully");
        return http.build();
    }

    // =====================================================================
    // 401 Unauthorized Handler → ApiResponse format
    // =====================================================================
    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return (request, response, ex) -> {
            log.warn("Unauthorized request to {}: {}", request.getRequestURI(), ex.getMessage());
            writeErrorResponse(
                    request, response,
                    HttpStatus.UNAUTHORIZED,
                    "AUTHENTICATION_FAILED",
                    "Authentication required"
            );
        };
    }

    // =====================================================================
    // 403 Forbidden Handler → ApiResponse format
    // =====================================================================
    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, ex) -> {
            log.warn("Forbidden request to {}: {}", request.getRequestURI(), ex.getMessage());
            writeErrorResponse(
                    request, response,
                    HttpStatus.FORBIDDEN,
                    "ACCESS_DENIED",
                    "Access denied"
            );
        };
    }

    // =====================================================================
    // Helper → Standardized JSON error response
    // =====================================================================
    private void writeErrorResponse(
            HttpServletRequest request,
            HttpServletResponse response,
            HttpStatus status,
            String code,
            String message
    ) throws IOException {

        ApiResponse<Void> body = ApiResponse.error(
                code,
                message,
                request.getRequestURI()
        );

        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getOutputStream(), body);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config)
            throws Exception {
        log.info("SecurityConfig: Creating AuthenticationManager bean");
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        log.info("SecurityConfig: Creating BCryptPasswordEncoder bean");
        return new BCryptPasswordEncoder();
    }
}


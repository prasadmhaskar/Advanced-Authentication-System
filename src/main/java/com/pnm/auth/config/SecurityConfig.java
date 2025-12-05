package com.pnm.auth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pnm.auth.dto.response.ApiResponse;
import com.pnm.auth.security.filter.JwtAuthenticationFilter;
import com.pnm.auth.security.filter.RedisRateLimiterFilter;
import com.pnm.auth.security.filter.RequestLoggingFilter;
import com.pnm.auth.security.filter.SecurityHeadersFilter;
import com.pnm.auth.security.oauth.OAuth2SuccessHandler;
import com.pnm.auth.security.UserDetailsServiceImpl;
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
                                "/api/auth/refresh",
                                "/api/auth/forgot-password",
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

        // ---------------------------------------------------------
        // FILTER ORDER (VERY IMPORTANT)
        // ---------------------------------------------------------
        // 1️⃣ RequestLoggingFilter → MDC setup (requestId, ip, ua, path)
        http.addFilterBefore(requestLoggingFilter, UsernamePasswordAuthenticationFilter.class);

        // 2️⃣ SecurityHeadersFilter → security headers for ALL responses
        http.addFilterBefore(securityHeadersFilter, RequestLoggingFilter.class);

        // 3️⃣ RedisRateLimiterFilter → uses MDC IP/path
        http.addFilterBefore(redisRateLimiterFilter, RequestLoggingFilter.class);

        // 4️⃣ JWT Authentication Filter → after logging & rate limit
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


package com.pnm.auth.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pnm.auth.dto.response.ApiResponse;
import com.pnm.auth.security.filter.*;
import com.pnm.auth.security.oauth.CookieOAuth2AuthorizationRequestRepository;
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
    private final CookieOAuth2AuthorizationRequestRepository cookieOAuth2AuthorizationRequestRepository;

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
                                "/api/auth/otp/verify",
                                "/api/auth/otp/resend",
                                "/api/auth/forgot-password",
                                "/api/auth/setup-password",
                                "/api/auth/link-oauth",
                                "/oauth2/**",
                                "/login/oauth2/**"
                        ).permitAll()
                        .anyRequest().authenticated()
                )

                // -----------------------------------------------------
                // OAuth2 Login
                // -----------------------------------------------------
                .oauth2Login(oauth2 -> {
                    oauth2.authorizationEndpoint(auth -> auth.authorizationRequestRepository(cookieOAuth2AuthorizationRequestRepository));
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

// Register filters (correct order)
//// 1. Request context (MDC, IP, UA)
//        http.addFilterBefore(requestLoggingFilter, UsernamePasswordAuthenticationFilter.class);
//// 2. Rate limiter (needs IP, path, MDC)
//        http.addFilterAfter(redisRateLimiterFilter, RequestLoggingFilter.class);
//// 3. Block invalid HTTP methods
//        http.addFilterAfter(blockHttpMethodsFilter, RedisRateLimiterFilter.class);
//// 4. OAuth redirect validation
//        http.addFilterAfter(oauthRedirectValidationFilter, RedisRateLimiterFilter.class);
//// 5. JWT authentication
//        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
//// 6. Security headers (last)
//        http.addFilterAfter(securityHeadersFilter, JwtAuthenticationFilter.class);

        // ---------------------------
// Register filters (Robust Anchoring)
// ---------------------------

// 1. Logging - Run this as early as possible (e.g., before the Security Context is even loaded)
// Anchor: ChannelProcessingFilter is typically the very first filter.
        http.addFilterBefore(requestLoggingFilter, org.springframework.security.web.access.channel.ChannelProcessingFilter.class);

// 2. Block Bad Methods - Run early to reject requests before wasting resources on Rate Limiting
// Anchor: HeaderWriterFilter usually runs after context setup but before Auth.
        http.addFilterBefore(blockHttpMethodsFilter, org.springframework.security.web.header.HeaderWriterFilter.class);

// 3. Rate Limiter - Run before we attempt any expensive authentication logic
// Anchor: UsernamePasswordAuthenticationFilter is the standard "Auth" phase.
// We add "Before" it, so we limit rates before checking passwords/tokens.
        http.addFilterBefore(redisRateLimiterFilter, UsernamePasswordAuthenticationFilter.class);

// 4. OAuth Redirect Validation - Specific check, can also run just before Auth
// Note: Since we are adding multiple filters "Before" the same class,
// the order of these lines matters (FIFO).
        http.addFilterBefore(oauthRedirectValidationFilter, UsernamePasswordAuthenticationFilter.class);

// 5. JWT Authentication - The core auth logic
// This must run before the standard UsernamePasswordAuthenticationFilter
// so we can populate the context with our JWT user.
        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

// 6. Security Headers - If this is a custom header filter, you can place it
// after the standard HeaderWriterFilter to append/override defaults.
        http.addFilterAfter(securityHeadersFilter, org.springframework.security.web.header.HeaderWriterFilter.class);


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


package com.pnm.auth.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pnm.auth.dto.response.ApiResponse;
import com.pnm.auth.security.filter.*;
import com.pnm.auth.security.oauth.CookieOAuth2AuthorizationRequestRepository;
import com.pnm.auth.security.oauth.OAuth2SuccessHandler;
import com.pnm.auth.web.filter.RequestContextFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
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
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.HeaderWriterFilter;

import java.io.IOException;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@Slf4j
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtFilter;
    private final UserDetailsService userDetailsService;
    private final OAuth2SuccessHandler oAuth2SuccessHandler;
    private final RedisRateLimiterFilter redisRateLimiterFilter;
    private final RequestLoggingFilter requestLoggingFilter;
    private final SecurityHeadersFilter securityHeadersFilter;
    private final ObjectMapper objectMapper;
    private final BlockHttpMethodsFilter blockHttpMethodsFilter;
    private final OAuthRedirectValidationFilter oauthRedirectValidationFilter;
    private final CookieOAuth2AuthorizationRequestRepository cookieOAuth2AuthorizationRequestRepository;

    RequestContextFilter requestContextFilter = new RequestContextFilter();

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
                        .requestMatchers("/api/admin/**", "/actuator/**").hasRole("ADMIN")
                        .requestMatchers("/api/user/**").hasAnyRole("USER", "ADMIN")
                        .requestMatchers(
                                "/api/auth/register",
                                "/api/auth/login",
                                "/api/auth/verify",
                                "/api/auth/verify/resend",
                                "/api/auth/refresh",
                                "/api/auth/otp/verify",
                                "/api/auth/otp/resend",
                                "/api/auth/forgot-password/**",
                                "/api/auth/reset-password/**",
                                "/api/auth/setup-password",
                                "/api/auth/link-oauth",
                                "/oauth2/**",
                                "/login/oauth2/**",
                                "/v3/api-docs/**",
                                "/swagger-ui/**",
                                "/swagger-ui.html",
                                "/favicon.ico"
                        ).permitAll()
                        .requestMatchers("/error").permitAll()
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
                .userDetailsService(userDetailsService);

// ---------------------------
// Register filters (Robust Anchoring)
// ---------------------------

        // 1. Request Context (IP/Agent extraction) - MUST BE FIRST
        // Anchor: ChannelProcessingFilter is the first standard Spring Security filter.
        http.addFilterBefore(requestContextFilter, ChannelProcessingFilter.class);

        // 2. Logging - Logs the request (needs Context from step 1)
        http.addFilterAfter(requestLoggingFilter, RequestContextFilter.class);

        // 3. Block Bad HTTP Methods - Run early to save resources
        http.addFilterAfter(blockHttpMethodsFilter, RequestLoggingFilter.class);

        // 4. Rate Limiter - Run before we touch any Auth logic (expensive)
        // Anchor: UsernamePasswordAuthenticationFilter is where Auth starts.
        http.addFilterBefore(redisRateLimiterFilter, UsernamePasswordAuthenticationFilter.class);

        // 5. OAuth Redirect Validation - Specific check for OAuth flows
        http.addFilterBefore(oauthRedirectValidationFilter, UsernamePasswordAuthenticationFilter.class);

        // 6. JWT Authentication - The core custom auth
        // Must run before UsernamePasswordAuthenticationFilter to populate SecurityContext
        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        // 7. Security Headers - Add custom headers to response
        http.addFilterAfter(securityHeadersFilter, HeaderWriterFilter.class);

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


    @Bean
    public FilterRegistrationBean<RequestContextFilter> requestContextFilterRegistration() {
        RequestContextFilter filter = new RequestContextFilter();
        FilterRegistrationBean<RequestContextFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false); // prevent Spring Boot from auto-registering this filter as a servlet filter
        return registration;
    }




}


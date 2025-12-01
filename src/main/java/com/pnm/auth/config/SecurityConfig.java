package com.pnm.auth.config;

import com.pnm.auth.security.filter.JwtAuthenticationFilter;
import com.pnm.auth.security.filter.RateLimiterFilter;
import com.pnm.auth.security.oauth.OAuth2SuccessHandler;
import com.pnm.auth.security.UserDetailsServiceImpl;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@Slf4j
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtFilter;
    private final UserDetailsServiceImpl userDetailsServiceImpl;
    private final OAuth2SuccessHandler oAuth2SuccessHandler;
    private final RateLimiterFilter rateLimiterFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        log.info("SecurityConfig.SecurityFilterChain: Initialized");

        http
                .cors(cors -> {
                    log.info("SecurityConfig: Enabling CORS support");
                })
                .csrf(csrf -> {
                    log.info("SecurityConfig: Disabling CSRF");
                    csrf.disable();
                })
                .authorizeHttpRequests(auth -> {
                    log.info("SecurityConfig: Configuring authorization rules");
                    auth.requestMatchers("/api/admin/**").hasRole("ADMIN");
                    auth.requestMatchers("/api/user/**").hasAnyRole("USER", "ADMIN");
                    auth.requestMatchers(
                                    "/api/auth/register",
                                    "/api/auth/login",
                                    "/api/auth/verify",
                                    "/api/auth/refresh",
                                    "/oauth2/**",
                                    "/login/oauth2/**",
                                    "/api/auth/logout"
                            )
                            .permitAll()
                            .anyRequest()
                            .authenticated();
                })
                .sessionManagement(session -> {
                    log.info("SecurityConfig: Setting session to STATELESS");
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                })
                .userDetailsService(userDetailsServiceImpl)
                .oauth2Login(oauth2 -> {
                    log.info("SecurityConfig: Setting OAuth2 Login Handlers");

                    oauth2.failureHandler((request, response, exception) -> {
                        log.error("SecurityConfig: OAuth2 failure -> {}", exception.getMessage());
                    });

                    oauth2.successHandler(oAuth2SuccessHandler);
                })
                .addFilterBefore(rateLimiterFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        log.info("SecurityConfig: SecurityFilterChain built successfully");
        return http.build();
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


package com.pnm.auth.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.List;

@Configuration
@Slf4j
public class CorsConfig {

    @Bean
    public CorsFilter corsFilter() {

        log.info("CorsConfig: Initializing CORS configuration");

        CorsConfiguration config = new CorsConfiguration();

        // Allowed origins
        config.setAllowedOrigins(List.of("http://localhost:3000"));
        log.info("CorsConfig: Allowed origins -> {}", config.getAllowedOrigins());

        // Allowed headers
        config.setAllowedHeaders(List.of("Authorization", "Content-Type", "Accept"));
        log.info("CorsConfig: Allowed headers -> {}", config.getAllowedHeaders());

        // Allowed methods
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        log.info("CorsConfig: Allowed methods -> {}", config.getAllowedMethods());

        // Allow sending cookies, tokens
        config.setAllowCredentials(true);
        log.info("CorsConfig: Credentials allowed -> {}", config.getAllowCredentials());

        // Exposed headers
        config.setExposedHeaders(List.of("Authorization"));
        log.info("CorsConfig: Exposed headers -> {}", config.getExposedHeaders());

        // Preflight cache time
        config.setMaxAge(3600L);
        log.info("CorsConfig: MaxAge (preflight caching) -> {} seconds", config.getMaxAge());

        // Apply to all paths
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        log.info("CorsConfig: CORS applied to all endpoints -> /**");

        log.info("CorsConfig: CORS Filter successfully created");

        return new CorsFilter(source);
    }
}

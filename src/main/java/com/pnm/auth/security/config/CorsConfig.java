package com.pnm.auth.security.config;

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

        // Match dev + prod dynamically
        config.setAllowedOriginPatterns(List.of(
                "http://localhost:*",
                "https://*.yourfrontend.com"
        ));

        config.setAllowedHeaders(List.of("*"));
        config.setAllowedMethods(List.of("*"));

        // Allow cookies + Authorization header + refresh tokens
        config.setAllowCredentials(true);

        config.setExposedHeaders(List.of(
                "Authorization",
                "X-Refresh-Token",
                "X-Request-Id"
        ));

        config.setMaxAge(86400L);  // Preflight caching

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        log.info("CorsConfig: CORS Filter successfully created");

        return new CorsFilter(source);
    }
}

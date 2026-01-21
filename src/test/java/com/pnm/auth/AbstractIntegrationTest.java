package com.pnm.auth;

import jakarta.annotation.PreDestroy;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import redis.embedded.RedisServer;

import java.io.IOException;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
public abstract class AbstractIntegrationTest {

    private static RedisServer redisServer;

    static {
        // Static block to ensure Redis starts only once per JVM
        try {
            // Bind to a random port or fixed port (6370 to avoid conflict with your real 6379)
            redisServer = new RedisServer(6370);
            redisServer.start();
            System.out.println("✅ Embedded Redis started on port 6370");
        } catch (Exception e) {
            System.err.println("⚠️ Redis failed to start (might be already running): " + e.getMessage());
        }
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        // 1. Configure H2 to emulate PostgreSQL
        // MODE=PostgreSQL allows H2 to understand Postgres-specific syntax
        registry.add("spring.datasource.url", () -> "jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1;MODE=PostgreSQL");
        registry.add("spring.datasource.username", () -> "sa");
        registry.add("spring.datasource.password", () -> "");
        registry.add("spring.datasource.driver-class-name", () -> "org.h2.Driver");

        // Disable Flyway clean-on-validation errors for H2
        registry.add("spring.flyway.clean-disabled", () -> "true");
        // Ensure Hibernate uses H2 dialect
        registry.add("spring.jpa.database-platform", () -> "org.hibernate.dialect.H2Dialect");

        // 2. Configure Embedded Redis
        registry.add("spring.data.redis.host", () -> "localhost");
        registry.add("spring.data.redis.port", () -> 6370);
    }

    @PreDestroy
    public void stopRedis() throws IOException {
        if (redisServer != null && redisServer.isActive()) {
            redisServer.stop();
        }
    }
}
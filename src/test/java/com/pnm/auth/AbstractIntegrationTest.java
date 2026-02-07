package com.pnm.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pnm.auth.repository.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cache.CacheManager;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

import java.util.Objects;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@ActiveProfiles("test")
// REMOVED: @Testcontainers annotation (Critical change!)
public abstract class AbstractIntegrationTest {

    // --- INFRASTRUCTURE (Singleton Pattern) ---

    // Define as static final so they are shared across all test classes
    static final PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15")
            .withDatabaseName("testdb")
            .withUsername("test")
            .withPassword("test")
            .waitingFor(Wait.forLogMessage(".*database system is ready to accept connections.*\\s", 2));

    static final GenericContainer<?> redis = new GenericContainer<>(DockerImageName.parse("redis:7"))
            .withExposedPorts(6379)
            .waitingFor(Wait.forLogMessage(".*Ready to accept connections.*\\s", 1));

    static {
        // Manually start containers ONCE. They will remain running for the entire JVM lifetime.
        postgres.start();
        redis.start();
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        // --- POSTGRES CONFIG (Force IPv4 for Linux stability) ---
        registry.add("spring.datasource.url", () -> postgres.getJdbcUrl().replace("localhost", "127.0.0.1"));
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");

        // --- FLYWAY CONFIG ---
        registry.add("spring.flyway.enabled", () -> "true");
        registry.add("spring.flyway.url", () -> postgres.getJdbcUrl().replace("localhost", "127.0.0.1"));
        registry.add("spring.flyway.user", postgres::getUsername);
        registry.add("spring.flyway.password", postgres::getPassword);

        // --- REDIS CONFIG ---
        registry.add("spring.data.redis.host", redis::getHost);
        registry.add("spring.data.redis.port", redis::getFirstMappedPort);
    }

    // --- TOOLS ---
    @Autowired protected MockMvc mockMvc;
    @Autowired protected ObjectMapper objectMapper;

    // --- REPOSITORIES ---
    @Autowired protected UserRepository userRepository;
    @Autowired protected VerificationTokenRepository verificationTokenRepository;
    @Autowired protected RefreshTokenRepository refreshTokenRepository;
    @Autowired protected MfaTokenRepository mfaTokenRepository;
    @Autowired protected AuditLogRepository auditLogRepository;
    @Autowired protected UserOAuthProviderRepository userOAuthProviderRepository;
    @Autowired protected AccountLinkTokenRepository accountLinkTokenRepository;
    @Autowired protected UserActivityRepository userActivityRepository;
    @Autowired protected UserIpLogRepository userIpLogRepository;

    // --- HELPERS ---
    @Autowired protected RedisTemplate<String, Object> redisTemplate;
    @Autowired protected CacheManager cacheManager;

    @MockitoBean protected JavaMailSender javaMailSender;

    @BeforeEach
    void setUp() { }

    @AfterEach
    void tearDown() {
        // Cleanup strictly ordered by Foreign Keys
        mfaTokenRepository.deleteAll();
        refreshTokenRepository.deleteAll();
        verificationTokenRepository.deleteAll();
        accountLinkTokenRepository.deleteAll();
        userOAuthProviderRepository.deleteAll();
        userActivityRepository.deleteAll();
        userIpLogRepository.deleteAll();
        auditLogRepository.deleteAll();
        userRepository.deleteAll(); // Parent table last

        // Flush Redis
        if (redisTemplate.getConnectionFactory() != null) {
            Objects.requireNonNull(redisTemplate.getConnectionFactory()).getConnection().serverCommands().flushAll();
        }

        // Clear Caches
        if (cacheManager != null) {
            cacheManager.getCacheNames().forEach(name ->
                    Objects.requireNonNull(cacheManager.getCache(name)).clear()
            );
        }
    }
}
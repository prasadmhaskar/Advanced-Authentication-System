package com.pnm.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pnm.auth.repository.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
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
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.util.Objects;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test") // Forces use of application-test.properties for non-overridden values
public abstract class AbstractIntegrationTest {

    // --- INFRASTRUCTURE (The "Hardcore" Part) ---

    @Container
    @ServiceConnection // Spring Boot 3.1+ magic: auto-configures datasource properties
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15-alpine");

    @Container
    static GenericContainer<?> redis = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
            .withExposedPorts(6379);

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        // Manually map Redis properties since @ServiceConnection for Redis can sometimes be finicky with specific clients
        registry.add("spring.data.redis.host", redis::getHost);
        registry.add("spring.data.redis.port", redis::getFirstMappedPort);

        // Force Flyway to run against the container
        registry.add("spring.flyway.enabled", () -> "true");
        // Overwrite H2 driver from application-test.properties
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
    }

    // --- TOOLS FOR TESTS ---

    @Autowired
    protected MockMvc mockMvc;

    @Autowired
    protected ObjectMapper objectMapper;

    // --- REPOSITORIES (For asserting state directly in DB) ---
    @Autowired protected UserRepository userRepository;
    @Autowired protected VerificationTokenRepository verificationTokenRepository;
    @Autowired protected RefreshTokenRepository refreshTokenRepository;
    @Autowired protected MfaTokenRepository mfaTokenRepository;
    @Autowired protected AuditLogRepository auditLogRepository;
    @Autowired protected UserOAuthProviderRepository userOAuthProviderRepository;
    @Autowired protected AccountLinkTokenRepository accountLinkTokenRepository;
    @Autowired protected UserActivityRepository userActivityRepository;
    @Autowired protected UserIpLogRepository userIpLogRepository;

    // --- REDIS/CACHE HELPERS ---
    @Autowired protected RedisTemplate<String, Object> redisTemplate;
    @Autowired protected CacheManager cacheManager;

    // --- EXTERNAL MOCKS ---
    // We mock the sender, not the service, so we can verify EmailService built the correct message
    @MockitoBean
    protected JavaMailSender javaMailSender;

    // If you have external GeoIP calls or similar that require internet, Mock them here too.
    // @MockBean protected GeoIpService geoIpService;

    @BeforeEach
    void setUp() {
        // Any setup required before EVERY test
    }

    @AfterEach
    void tearDown() {
        // BRUTAL CLEANUP: Ensure no state leaks between tests
        // Order matters due to foreign keys
        mfaTokenRepository.deleteAll();
        refreshTokenRepository.deleteAll();
        verificationTokenRepository.deleteAll();
        accountLinkTokenRepository.deleteAll();
        userOAuthProviderRepository.deleteAll();
        userActivityRepository.deleteAll();
        userIpLogRepository.deleteAll();
        auditLogRepository.deleteAll();
        userRepository.deleteAll();

        // Clear Redis
        Objects.requireNonNull(redisTemplate.getConnectionFactory()).getConnection().serverCommands().flushAll();
        // Clear Spring Caches
        cacheManager.getCacheNames().forEach(cacheName ->
                Objects.requireNonNull(cacheManager.getCache(cacheName)).clear()
        );
    }
}
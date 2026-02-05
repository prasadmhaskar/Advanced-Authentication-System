package com.pnm.auth.integration;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.mockito.Mockito;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.context.ActiveProfiles;

import redis.embedded.RedisServer;

import java.io.IOException;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(IntegrationTestBase.TestConfig.class)
public abstract class IntegrationTestBase {

    private static final int REDIS_PORT = 6370;
    private static RedisServer redisServer;

    @BeforeAll
    void startRedis() throws IOException {
        if (redisServer == null) {
            redisServer = new RedisServer(REDIS_PORT);
            redisServer.start();
        }
    }

    @AfterAll
    void stopRedis() throws IOException {
        if (redisServer != null) {
            redisServer.stop();
            redisServer = null;
        }
    }

    @TestConfiguration
    static class TestConfig {

        @Bean
        JavaMailSender javaMailSender() {
            return Mockito.mock(JavaMailSender.class);
        }
    }
}

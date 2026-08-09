package com.pnm.auth.util;

import com.pnm.auth.domain.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.crypto.SecretKey;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class JwtUtilUnitTest {

    private static final String BASE64_SECRET = Base64.getEncoder()
            .encodeToString("01234567890123456789012345678901".getBytes(StandardCharsets.UTF_8));

    private JwtUtil jwtUtil;

    @BeforeEach
    void setUp() throws Exception {
        jwtUtil = new JwtUtil();
        setField(jwtUtil, "jwtSecretKey", BASE64_SECRET);
        setField(jwtUtil, "jwtAccessExpiration", 60_000L);
        setField(jwtUtil, "jwtIssuer", "advanced-auth-system");
        setField(jwtUtil, "jwtAudience", "advanced-auth-api");
        jwtUtil.init();
    }

    @Test
    @DisplayName("generateAccessToken should include subject, roles, and custom claims")
    void generateAccessToken_includesClaims() {
        User user = buildUser();

        String token = jwtUtil.generateAccessToken(user);

        assertNotNull(token);
        assertEquals(user.getEmail(), jwtUtil.extractUsername(token));
        assertEquals(user.getRoles(), jwtUtil.extractRoles(token));

        Claims claims = jwtUtil.parseAccessToken(token);
        assertEquals(user.getEmail(), claims.getSubject());
        assertEquals(user.getId().longValue(), ((Number) claims.get("userId")).longValue());
        assertEquals(user.getTokenVersion().longValue(), ((Number) claims.get("tv")).longValue());
        assertEquals("access", claims.get("token_use", String.class));
        assertFalse(jwtUtil.isTokenExpired(token));
    }

    @Test
    @DisplayName("parseAccessToken should reject a JWT intended for refresh")
    void parseAccessToken_rejectsNonAccessToken() {
        SecretKey signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(BASE64_SECRET));
        String token = Jwts.builder()
                .subject("user@example.com")
                .issuer("advanced-auth-system")
                .audience().add("advanced-auth-api").and()
                .claim("token_use", "refresh")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60_000L))
                .signWith(signingKey)
                .compact();

        assertThrows(IllegalArgumentException.class, () -> jwtUtil.parseAccessToken(token));
    }

    @Test
    @DisplayName("resolveToken should extract bearer token from Authorization header")
    void resolveToken_extractsBearerToken() {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getHeader("Authorization")).thenReturn("Bearer sample-token");

        assertEquals("sample-token", jwtUtil.resolveToken(request));
    }

    @Test
    @DisplayName("resolveToken should return null for missing bearer token")
    void resolveToken_returnsNullWhenMissing() {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getHeader("Authorization")).thenReturn("Token abc");

        assertNull(jwtUtil.resolveToken(request));
    }

    @Test
    @DisplayName("parseAccessToken should throw for expired tokens")
    void parseAccessToken_throwsOnExpiredToken() throws Exception {
        setField(jwtUtil, "jwtAccessExpiration", -1_000L);
        String token = jwtUtil.generateAccessToken(buildUser());

        assertThrows(ExpiredJwtException.class, () -> jwtUtil.parseAccessToken(token));
    }

    @Test
    @DisplayName("parseAccessToken should reject tokens signed with a different secret")
    void parseAccessToken_rejectsInvalidSignature() {
        String otherSecret = Base64.getEncoder()
                .encodeToString("different-secret-key-for-tests-123".getBytes(StandardCharsets.UTF_8));
        SecretKey otherKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(otherSecret));
        String token = Jwts.builder()
                .subject("user@example.com")
                .claim("roles", List.of("ROLE_USER"))
                .claim("token_use", "access")
                .issuer("advanced-auth-system")
                .audience().add("advanced-auth-api").and()
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60_000L))
                .signWith(otherKey)
                .compact();

        assertThrows(SignatureException.class, () -> jwtUtil.parseAccessToken(token));
    }

    @Test
    void getExpirationTimestamp_returnsExpirationTime(){
        String token = jwtUtil.generateAccessToken(buildUser());
        long expirationTimestamp = jwtUtil.getExpirationTimestamp(token);
        assertNotNull(expirationTimestamp);
    }

    private User buildUser() {
        User user = new User();
        user.setId(42L);
        user.setEmail("unit@test.com");
        user.setRoles(List.of("ROLE_USER", "ROLE_ADMIN"));
        user.setTokenVersion(2);
        return user;
    }

    private static void setField(Object target, String fieldName, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, value);
    }
}

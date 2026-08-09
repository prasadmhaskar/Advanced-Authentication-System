package com.pnm.auth.util;

import com.pnm.auth.domain.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Component
@Slf4j
public class JwtUtil {

    @Value("${jwt.secret}")
    private String jwtSecretKey;

    @Value("${jwt.access.expiration}")
    private Long jwtAccessExpiration;

    @Value("${jwt.issuer}")
    private String jwtIssuer;

    @Value("${jwt.audience}")
    private String jwtAudience;

    private SecretKey cachedSecretKey;

    @PostConstruct
    public void init() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecretKey);
        this.cachedSecretKey = Keys.hmacShaKeyFor(keyBytes);
    }

    private SecretKey getSigningKey() {
        return this.cachedSecretKey;
    }


    // ------------------------- TOKEN CREATION -------------------------

    public String generateAccessToken(User user) {
        log.info("JwtUtil.generateAccessToken: Generating access token for email={}", user.getEmail());
        String token = Jwts.builder()
                .subject(user.getEmail())
                .claim("userId", user.getId())
                .claim("roles", user.getRoles())
                .claim("tv", user.getTokenVersion())
                .claim("token_use", "access")
                .id(UUID.randomUUID().toString())
                .issuer(jwtIssuer)
                .audience().add(jwtAudience).and()
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + jwtAccessExpiration))
                .signWith(getSigningKey())
                .compact();

        log.debug("JwtUtil.generateAccessToken: Created access token for email={}", user.getEmail());
        return token;
    }

    // ------------------------- TOKEN EXTRACTION -------------------------

    public String extractUsername(String token) {
        log.debug("JwtUtil.extractUsername: Extracting username");
        return parseAccessToken(token).getSubject();
    }

    public List<String> extractRoles(String token) {
        log.debug("JwtUtil.extractRoles: Extracting roles");
        Claims claims = parseAccessToken(token);
        return claims.get("roles", List.class);
    }

    // ------------------------- TOKEN VALIDATION -------------------------

    public boolean isTokenExpired(String token) {
        boolean expired = parseAccessToken(token).getExpiration().before(new Date());
        log.info("JwtUtil.isTokenExpired: Checking token expired or not");
        return expired;
    }

    // ------------------------- CLAIMS -------------------------

    public Claims parseAccessToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(getSigningKey())
                    .requireIssuer(jwtIssuer)
                    .requireAudience(jwtAudience)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            if (!"access".equals(claims.get("token_use", String.class))) {
                throw new IllegalArgumentException("JWT is not an access token");
            }
            return claims;
        } catch (ExpiredJwtException e) {
            log.warn("JwtUtil: Token expired. Subject: {}", e.getClaims().getSubject());
            throw e;
        } catch (MalformedJwtException | SignatureException | IllegalArgumentException e) {
            log.warn("JwtUtil: Invalid token rejected. Message: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("JwtUtil: Unexpected error parsing token", e);
            throw e;
        }
    }

    public String resolveToken(HttpServletRequest request) {
        log.debug("JwtUtil.resolveToken: Attempting to extract JWT from Authorization header");
        String bearer = request.getHeader("Authorization");

        if (bearer != null && bearer.startsWith("Bearer ")) {
            String token = bearer.substring(7);
            log.info("JwtUtil.resolveToken: JWT extracted");
            return token;
        }

        log.warn("JwtUtil.resolveToken: No Bearer token found in request");
        return null;
    }

    public long getExpirationTimestamp(String token) {
        return parseAccessToken(token).getExpiration().getTime();
    }

}

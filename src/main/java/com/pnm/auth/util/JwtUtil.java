package com.pnm.auth.util;

import com.pnm.auth.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;

@Component
@Slf4j
public class JwtUtil {

    @Value("${jwt.secret}")
    private String jwtSecretKey;

    @Value("${jwt.access.expiration}")
    private Long jwtAccessExpiration;

    @Value("${jwt.refresh.expiration}")
    private Long jwtRefreshExpiration;

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(jwtSecretKey.getBytes());
    }

    // ------------------------- TOKEN CREATION -------------------------

    public String generateAccessToken(User user) {
        log.info("JwtUtil.generateAccessToken: Generating access token for email={}", user.getEmail());
        String token = Jwts.builder()
                .subject(user.getEmail())
                .claim("userId", user.getId())
                .claim("roles", user.getRoles())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + jwtAccessExpiration))
                .signWith(getSigningKey())
                .compact();

        log.info("JwtUtil.generateAccessToken: Token created tokenPrefix={}", token.substring(0, 10));
        return token;
    }

    public String generateRefreshToken(User user) {
        log.info("JwtUtil.generateRefreshToken: Generating refresh token for email={}", user.getEmail());
        String token = Jwts.builder()
                .subject(user.getEmail())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + jwtRefreshExpiration))
                .signWith(getSigningKey())
                .compact();

        log.info("JwtUtil.generateRefreshToken: Token created tokenPrefix={}", token.substring(0, 10));
        return token;
    }

    // ------------------------- TOKEN EXTRACTION -------------------------

    public String extractUsername(String token) {
        log.debug("JwtUtil.extractUsername: Extracting username tokenPrefix={}", safePrefix(token));
        return extractAllClaims(token).getSubject();
    }

    public List<String> extractRoles(String token) {
        log.debug("JwtUtil.extractRoles: Extracting roles tokenPrefix={}", safePrefix(token));
        Claims claims = extractAllClaims(token);
        return claims.get("roles", List.class);
    }

    // ------------------------- TOKEN VALIDATION -------------------------

    public boolean isTokenExpired(String token) {
        boolean expired = extractAllClaims(token).getExpiration().before(new Date());
        log.info("JwtUtil.isTokenExpired: tokenPrefix={} expired={}", safePrefix(token), expired);
        return expired;
    }

    public boolean isTokenValid(String token) {
        boolean valid = !isTokenExpired(token);
        log.info("JwtUtil.isTokenValid: tokenPrefix={} valid={}", safePrefix(token), valid);
        return valid;
    }

    // ------------------------- CLAIMS -------------------------

    private Claims extractAllClaims(String token) {
        try {
            log.debug("JwtUtil.extractAllClaims: Parsing claims tokenPrefix={}", safePrefix(token));
            return Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (Exception ex) {
            log.error("JwtUtil.extractAllClaims: Failed to parse token tokenPrefix={} error={}",
                    safePrefix(token), ex.getMessage());
            throw ex;
        }
    }

    public String resolveToken(HttpServletRequest request) {
        log.debug("JwtUtil.resolveToken: Attempting to extract JWT from Authorization header");
        String bearer = request.getHeader("Authorization");

        if (bearer != null && bearer.startsWith("Bearer ")) {
            String token = bearer.substring(7);
            log.info("JwtUtil.resolveToken: JWT extracted tokenPrefix={}", safePrefix(token));
            return token;
        }

        log.warn("JwtUtil.resolveToken: No Bearer token found in request");
        return null;
    }

    // ------------------------- SAFE TOKEN PREFIX -------------------------

    private String safePrefix(String token) {
        if (token == null) return "null";
        return token.length() > 10 ? token.substring(0, 10) : token;
    }
}

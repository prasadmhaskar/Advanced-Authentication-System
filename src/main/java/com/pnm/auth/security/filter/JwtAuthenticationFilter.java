package com.pnm.auth.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuditAction;
import com.pnm.auth.dto.response.ApiResponse;
import com.pnm.auth.dto.result.MfaResult;
import com.pnm.auth.dto.result.RiskResult;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.service.impl.auth.SessionCompromiseService;
import com.pnm.auth.service.impl.user.UserDetailsImpl;
import com.pnm.auth.service.interfaces.auth.MfaService;
import com.pnm.auth.service.interfaces.audit.AuditService;
import com.pnm.auth.service.interfaces.email.EmailService;
import com.pnm.auth.service.interfaces.risk.RiskEngineService;
import com.pnm.auth.util.BlacklistedTokenStore;
import com.pnm.auth.util.IpUtils;
import com.pnm.auth.util.JwtUtil;
import com.pnm.auth.util.MaskingUtil;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;
    private final BlacklistedTokenStore blacklistedTokenStore;
    private final ObjectMapper objectMapper;
    private final RiskEngineService riskEngineService;
    private final MfaService mfaService;
    private final UserRepository userRepository;
    private final SessionCompromiseService sessionCompromiseService;
    private final AuditService auditService;
    private final EmailService emailService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");
        String jwt = null;
        String username = null;
        Claims claims = null;

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

            jwt = authHeader.substring(7);

            try {
                claims = jwtUtil.parseAccessToken(jwt);
                username = claims.getSubject();
            } catch (Exception e) {
                log.warn("Invalid JWT: {}", e.getMessage());
            }

            // A token is parsed and verified as an access token before it can
            // reach any stateful checks.
            if (username != null && blacklistedTokenStore.isBlacklisted(jwt)) {
                log.warn("Blocked blacklisted token usage");
                writeError(response, request, "TOKEN_BLACKLISTED", "The token has been invalidated. Please login again.");
                return;
            }

        // Authentication block
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            UserDetailsImpl userDetails;
            try {
                userDetails = (UserDetailsImpl) userDetailsService.loadUserByUsername(username);
            } catch (Exception e) {
                log.warn("User not found for token: {}", MaskingUtil.maskEmail(username));
                filterChain.doFilter(request, response);
                return;
            }

            String ip = IpUtils.getClientIp(request);
            String userAgent = request.getHeader("User-Agent");

            if (!userDetails.isActive()) {
                log.warn("Blocked user attempted access: {}", MaskingUtil.maskEmail(username));
                filterChain.doFilter(request, response);
                return;
            }

            Integer tokenVersionInJwt = claims.get("tv", Integer.class);
            if (tokenVersionInJwt == null || !tokenVersionInJwt.equals(userDetails.getTokenVersion())) {
                log.warn("Token version mismatch for user={}", userDetails.getEmail());

                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);

                ApiResponse<Void> body = ApiResponse.error("TOKEN_REVOKED", "Session expired please login again", request.getRequestURI());

                objectMapper.writeValue(response.getOutputStream(), body);
                return;
            }

            RiskResult riskResult = riskEngineService.evaluateRisk(userDetails.getId(), ip, userAgent);

            if (riskResult.isBlocked()) {
                sessionCompromiseService.revokeAllSessions(userDetails.getId());
                blacklistCurrentToken(jwt);

                auditService.recordAudit(
                        AuditAction.ACCESS_TOKEN_COMPROMISE,
                        userDetails.getId(),
                        userDetails.getId(),
                        "High-risk access-token use detected; all sessions revoked",
                        ip,
                        userAgent
                );
                emailService.sendHighRiskAlert(userDetails.getEmail(), ip, userAgent, riskResult.getReasons());

                log.warn("JwtAuthenticationFilter: high-risk token use; all sessions revoked for email={}",
                        MaskingUtil.maskEmail(userDetails.getEmail()));

                writeError(response, request, "ACCOUNT_SECURITY_LOCKOUT",
                        "Suspicious activity was detected. All sessions have been signed out; please sign in again.");
                return;
            }

            if (riskResult.isOtpRequired()) {
                User user = userRepository.findById(userDetails.getId())
                        .orElseThrow(() -> new IllegalStateException("User disappeared during risk challenge"));
                MfaResult mfaResult = mfaService.handleMediumRiskOtp(user);
                blacklistCurrentToken(jwt);

                log.warn("JwtAuthenticationFilter: step-up authentication required for email={}",
                        MaskingUtil.maskEmail(userDetails.getEmail()));

                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);

                ApiResponse<MfaResult> body = ApiResponse.error(
                        "STEP_UP_AUTHENTICATION_REQUIRED",
                        "Suspicious activity detected. Complete the OTP verification to continue.",
                        request.getRequestURI()
                );
                body.setData(mfaResult);
                objectMapper.writeValue(response.getOutputStream(), body);
                return;
            }

            UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities()
                        );

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
        }
        filterChain.doFilter(request, response);
    }

    private void blacklistCurrentToken(String jwt) {
        blacklistedTokenStore.blacklistToken(jwt, jwtUtil.getExpirationTimestamp(jwt));
    }

    private void writeError(HttpServletResponse response, HttpServletRequest request,
                            String code, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getOutputStream(), ApiResponse.error(code, message, request.getRequestURI()));
    }
}

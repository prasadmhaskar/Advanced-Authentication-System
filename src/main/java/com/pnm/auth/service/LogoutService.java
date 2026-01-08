package com.pnm.auth.service;

import com.pnm.auth.domain.entity.RefreshToken;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.dto.request.LogoutRequest;
import com.pnm.auth.exception.custom.InvalidCredentialsException;
import com.pnm.auth.exception.custom.InvalidTokenException;
import com.pnm.auth.exception.custom.UserNotFoundException;
import com.pnm.auth.repository.RefreshTokenRepository;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.util.JwtUtil;
import com.pnm.auth.web.context.RequestContext;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class LogoutService {

    private final JwtUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    @Transactional
    public void logout(
            LogoutRequest request,
            HttpServletRequest httpServletRequest,
            RequestContext ctx
    ) {
        String ip = ctx.ip();

        log.info("LogoutService: started ip={}", ip);

        // Extract access token from header
        String accessToken = extractAccessToken(httpServletRequest);

        // Extract user email
        String email;
        try {
            email = jwtUtil.extractAllClaims(accessToken).getSubject();
        } catch (Exception e) {
            throw new InvalidTokenException("Invalid access token");
        }

        // Refresh token validation
        if (request != null && request.getRefreshToken() != null) {
            RefreshToken refreshToken = refreshTokenRepository
                    .findByToken(request.getRefreshToken())
                    .orElseThrow(() -> new InvalidTokenException("Invalid refresh token"));

            if (!refreshToken.getUser().getEmail().equals(email)) {
                throw new InvalidCredentialsException("Token ownership mismatch");
            }

            refreshTokenRepository.delete(refreshToken);
        }

        // if a user selects logout from all devices, then we will do this
        if (request != null && request.getLogoutFromAllDevices()){
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new UserNotFoundException("User not found"));

            // Kill refresh token via token Version
            user.incrementTokenVersion();
            userRepository.save(user);

            refreshTokenRepository.deleteByUserId(user.getId());

        }

        log.info("LogoutService: finished ip={} email={}", ip, email);
    }

    private String extractAccessToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");

        if (header == null || !header.startsWith("Bearer ")) {
            throw new InvalidTokenException("Missing Authorization header");
        }
        return header.substring(7);
    }
}


package com.pnm.auth.service;

import com.pnm.auth.dto.request.*;
import com.pnm.auth.dto.response.AuthResponse;
import com.pnm.auth.dto.response.UserDetailsResponse;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.user.OAuth2User;


public interface AuthService {

    AuthResponse register(RegisterRequest request);

    AuthResponse login(LoginRequest request);

    AuthResponse refreshToken(RefreshTokenRequest refreshToken);

    void forgotPassword(String email);

    void resetPassword(ResetPasswordRequest request);

    UserDetailsResponse userDetailsFromAccessToken(String token);

    void logout( String refreshToken);

    void linkOAuthAccount(LinkOAuthRequest request);
}

package com.pnm.auth.service;

import com.pnm.auth.dto.request.LoginRequest;
import com.pnm.auth.dto.request.RefreshTokenRequest;
import com.pnm.auth.dto.request.RegisterRequest;
import com.pnm.auth.dto.request.ResetPasswordRequest;
import com.pnm.auth.dto.response.AuthResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.user.OAuth2User;


public interface AuthService {

    AuthResponse register(RegisterRequest request);

    AuthResponse login(LoginRequest request);

    AuthResponse refreshToken(RefreshTokenRequest refreshToken);

    void forgotPassword(String email);

    void resetPassword(ResetPasswordRequest request);

    public AuthResponse handleOAuth2LoginRequest(OAuth2User oAuth2User, String registrationId);

}

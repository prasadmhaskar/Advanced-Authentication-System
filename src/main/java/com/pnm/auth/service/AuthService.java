package com.pnm.auth.service;

import com.pnm.auth.dto.request.LoginRequest;
import com.pnm.auth.dto.request.RefreshTokenRequest;
import com.pnm.auth.dto.request.RegisterRequest;
import com.pnm.auth.dto.request.ResetPasswordRequest;
import com.pnm.auth.dto.response.AuthResponse;


public interface AuthService {

    AuthResponse register(RegisterRequest request);

    AuthResponse login(LoginRequest request);

    AuthResponse refreshToken(RefreshTokenRequest refreshToken);

    void forgotPassword(String email);

    void resetPassword(ResetPasswordRequest request);

}

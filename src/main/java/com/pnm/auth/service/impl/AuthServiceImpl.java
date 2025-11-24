package com.pnm.auth.service.impl;

import com.pnm.auth.dto.request.LoginRequest;
import com.pnm.auth.dto.request.RegisterRequest;
import com.pnm.auth.dto.response.AuthResponse;
import com.pnm.auth.service.AuthService;

public class AuthServiceImpl implements AuthService {
    @Override
    public AuthResponse register(RegisterRequest request) {
        return null;
    }

    @Override
    public AuthResponse login(LoginRequest request) {
        return null;
    }

    @Override
    public AuthResponse refreshToken(String refreshToken) {
        return null;
    }
}

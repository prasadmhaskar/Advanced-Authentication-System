package com.pnm.auth.service;

import com.pnm.auth.dto.request.*;
import com.pnm.auth.dto.response.*;


public interface AuthService {

    AuthResponse register(RegisterRequest request);

    AuthResponse login(LoginRequest request);

    AuthResponse refreshToken(RefreshTokenRequest refreshToken);

    void forgotPassword(String email);

    void resetPassword(ResetPasswordRequest request);

    UserDetailsResponse userDetailsFromAccessToken(String token);

    void logout(String accessToken, String refreshToken);

    void linkOAuthAccount(LinkOAuthRequest request);

}

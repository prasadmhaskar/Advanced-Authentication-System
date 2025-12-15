package com.pnm.auth.service.auth;

import com.pnm.auth.dto.request.*;
import com.pnm.auth.dto.response.*;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;


public interface AuthService {

    AuthResponse register(RegisterRequest request);

    AuthResponse login(LoginRequest request, String ip, String userAgent);

    AuthResponse refreshToken(RefreshTokenRequest refreshToken);

    void forgotPassword(String email);

    void resetPassword(ResetPasswordRequest request);

    UserDetailsResponse userDetailsFromAccessToken(String token);

    void logout(String accessToken, String refreshToken);

    void linkOAuthAccount(LinkOAuthRequest request);

    AuthResponse changePassword(String token, @NotBlank String oldPassword, @NotBlank String newPassword);

    UserDetailsResponse updateProfile(String accessToken, UpdateProfileRequest request);

    AuthResponse verifyOtp(@Valid MfaTokenVerifyRequest mfaTokenVerifyRequest, String ip, String userAgent);
}

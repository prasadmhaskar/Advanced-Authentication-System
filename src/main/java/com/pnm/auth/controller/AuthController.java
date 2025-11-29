package com.pnm.auth.controller;

import com.pnm.auth.dto.request.*;
import com.pnm.auth.dto.response.AuthResponse;
import com.pnm.auth.dto.response.UserDetailsResponse;
import com.pnm.auth.service.AuthService;
import com.pnm.auth.service.VerificationService;
import com.pnm.auth.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;
    private final VerificationService verificationService;
    private final JwtUtil jwtUtil;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest registerRequest) {
        log.info("AuthController.register(): started for email={}", registerRequest.getEmail());
        AuthResponse response = authService.register(registerRequest);
        log.info("AuthController.register(): Finished for email={}", registerRequest.getEmail());
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    @GetMapping("/verify")
    public ResponseEntity<String> verifyEmail(@RequestParam("token") String token) {
        log.info("AuthController.verifyEmail(): Started");
        verificationService.validateToken(token, "EMAIL_VERIFICATION");
        log.info("AuthController.verifyEmail(): Finished");
        return new ResponseEntity<>("Email verification successful", HttpStatus.OK);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest loginRequest) {
        log.info("AuthController.login(): Started for email={}", loginRequest.getEmail());
        AuthResponse response = authService.login(loginRequest);
        log.info("AuthController.login(): Finished for email={}", loginRequest.getEmail());
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> verifyRefreshToken(@Valid @RequestBody RefreshTokenRequest refreshTokenRequest){
        log.info("AuthController.verifyRefreshToken(): Started");
        AuthResponse response = authService.refreshToken(refreshTokenRequest);
        log.info("AuthController.verifyRefreshToken(): Finished");
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        log.info("AuthController.forgotPassword(): Started for email={}", request.getEmail());
        authService.forgotPassword(request.getEmail());
        log.info("AuthController.forgotPassword(): Finished for email={}", request.getEmail());
        return ResponseEntity.ok("Password reset link sent to email");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@Valid @RequestBody ResetPasswordRequest resetPasswordRequest) {
        log.info("AuthController.resetPassword(): Started");
        authService.resetPassword(resetPasswordRequest);
        log.info("AuthController.resetPassword(): Finished");
        return ResponseEntity.ok("Password updated successfully");
    }

    @GetMapping("/me")
    public ResponseEntity<UserDetailsResponse> fetchUserDetails(HttpServletRequest request) {
        log.info("AuthController.fetchUserDetails(): Started");
        String token = jwtUtil.resolveToken(request);
        UserDetailsResponse response = authService.userDetailsFromAccessToken(token);
        log.info("AuthController.fetchUserDetails(): Finished for email={}", response.getEmail());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody RefreshTokenRequest request) {
        log.info("AuthController.logout(): Started");
        authService.logout(request.getRefreshToken());
        log.info("AuthController.logout(): Finished");
        return ResponseEntity.ok("Logged out successfully.");
    }

    @PostMapping("/link-oauth")
    public ResponseEntity<String> linkOAuth(@RequestBody LinkOAuthRequest request) {
        log.info("AuthController.linkOAuth(): Started");
        authService.linkOAuthAccount(request);
        log.info("AuthController.linkOAuth(): Finished");
        return ResponseEntity.ok("OAuth account linked successfully");
    }
}
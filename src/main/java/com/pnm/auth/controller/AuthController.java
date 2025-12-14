package com.pnm.auth.controller;

import com.pnm.auth.dto.DeviceInfo;
import com.pnm.auth.dto.request.*;
import com.pnm.auth.dto.response.ApiResponse;
import com.pnm.auth.dto.response.AuthResponse;
import com.pnm.auth.dto.response.TrustedDeviceResponse;
import com.pnm.auth.dto.response.UserDetailsResponse;
import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.dto.result.EmailVerificationResult;
import com.pnm.auth.dto.result.ForgotPasswordResult;
import com.pnm.auth.dto.result.RegistrationResult;
import com.pnm.auth.service.AuthService;
import com.pnm.auth.service.TrustedDeviceService;
import com.pnm.auth.service.VerificationService;
import com.pnm.auth.security.JwtUtil;
import com.pnm.auth.service.auth.*;
import com.pnm.auth.util.AuthUtil;
import com.pnm.auth.util.UserAgentParser;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;
    private final VerificationService verificationService;
    private final JwtUtil jwtUtil;
    private final TrustedDeviceService trustedDeviceService;
    private final AuthUtil authUtil;
    private final LoginOrchestrator loginOrchestrator;
    private final VerifyOtpOrchestrator verifyOtpOrchestrator;
    private final ResendOtpOrchestrator resendOtpOrchestrator;
    private final RegisterOrchestrator registerOrchestrator;
    private final VerifyEmailOrchestrator verifyEmailOrchestrator;
    private final ForgotPasswordOrchestrator forgotPasswordOrchestrator;
    private final ResetPasswordOrchestrator resetPasswordOrchestrator;
    private final RefreshTokenOrchestrator refreshTokenOrchestrator;
    private final UserContextOrchestrator userContextOrchestrator;
    private final LogoutOrchestrator logoutOrchestrator;
    private final LinkOAuthOrchestrator linkOAuthOrchestrator;
    private final ChangePasswordOrchestrator changePasswordOrchestrator;

//    @PostMapping("/register")
//    public ResponseEntity<ApiResponse<AuthResponse>> register(
//            @Valid @RequestBody RegisterRequest registerRequest,
//            HttpServletRequest request) {
//
//        log.info("AuthController.register(): started for email={}", registerRequest.getEmail());
//        AuthResponse response = authService.register(registerRequest);
//        log.info("AuthController.register(): Finished for email={}", registerRequest.getEmail());
//
//        ApiResponse<AuthResponse> body = ApiResponse.success(
//                "USER_REGISTERED",
//                response.getMessage(),
//                response,
//                request.getRequestURI()
//        );
//        return new ResponseEntity<>(body, HttpStatus.CREATED);
//    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<?>> register(
            @Valid @RequestBody RegisterRequest request,
            HttpServletRequest httpRequest
    ) {
        RegistrationResult result =
                registerOrchestrator.register(request);

        String path = httpRequest.getRequestURI();

        return switch (result.getOutcome()) {

            case REGISTERED -> ResponseEntity.status(HttpStatus.CREATED).body(
                    ApiResponse.success(
                            "USER_REGISTERED",
                            result.getMessage(),
                            result,
                            path
                    )
            );
            default -> ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    ApiResponse.error(
                            "REGISTRATION_FAILED",
                            result.getMessage(),
                            path
                    )
            );
        };
    }


//    @GetMapping("/verify")
//    public ResponseEntity<ApiResponse<Void>> verifyEmail(
//            @RequestParam("token") String token,
//            HttpServletRequest request) {
//
//        log.info("AuthController.verifyEmail(): Started");
//        verificationService.validateToken(token, "EMAIL_VERIFICATION");
//        log.info("AuthController.verifyEmail(): Finished");
//
//        ApiResponse<Void> body = ApiResponse.success(
//                "EMAIL_VERIFIED",
//                "Email verification successful",
//                null,
//                request.getRequestURI()
//        );
//        return ResponseEntity.ok(body);
//    }

    @GetMapping("/verify")
    public ResponseEntity<ApiResponse<?>> verifyEmail(
            @RequestParam("token") String token,
            HttpServletRequest request
    ) {
        EmailVerificationResult result =
                verifyEmailOrchestrator.verify(token);

        String path = request.getRequestURI();

        return switch (result.getOutcome()) {

            case SUCCESS -> ResponseEntity.ok(
                    ApiResponse.success(
                            "EMAIL_VERIFIED",
                            result.getMessage(),
                            result,
                            path
                    )
            );

            default -> ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    ApiResponse.error(
                            "EMAIL_VERIFICATION_FAILED",
                            result.getMessage(),
                            path
                    )
            );
        };
    }


//    @PostMapping("/login")
//    public ResponseEntity<ApiResponse<AuthResponse>> login(
//            @Valid @RequestBody LoginRequest loginRequest,
//            HttpServletRequest request) {
//
//        log.info("AuthController.login(): Started for email={}", loginRequest.getEmail());
//
//        String ip = request.getHeader("X-Forwarded-For");
//        if (ip == null) ip = request.getRemoteAddr();           //Fetching ip
//        String userAgent = request.getHeader("User-Agent");     //fetching browser/device info
//
//        AuthResponse response = authService.login(loginRequest, ip, userAgent);
//        log.info("AuthController.login(): Finished for email={}", loginRequest.getEmail());
//
//        ApiResponse<AuthResponse> body = ApiResponse.success(
//                "USER_LOGGED_IN",
//                response.getMessage(),
//                response,
//                request.getRequestURI()
//        );
//        return ResponseEntity.ok(body);
//    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<?>> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest
    ) {

        // Extract IP + User-Agent
        String ip = httpRequest.getHeader("X-Forwarded-For");
        if (ip == null) ip = httpRequest.getRemoteAddr();

        String ua = httpRequest.getHeader("User-Agent");

        log.info("AuthController.login(): started for email={} ip={} ua={}", request.getEmail(), ip, ua);

        // Call orchestrator
        AuthenticationResult result = loginOrchestrator.login(request, ip, ua);

        String path = httpRequest.getRequestURI();

        // Build HTTP response based on outcome
        return switch (result.getOutcome()) {

            case SUCCESS -> ResponseEntity.ok(
                    ApiResponse.success(
                            "LOGIN_SUCCESS",
                            result.getMessage(),
                            result,
                            path
                    )
            );
            case MFA_REQUIRED -> ResponseEntity.status(HttpStatus.OK).body(
                    ApiResponse.success(
                            "MFA_REQUIRED",
                            result.getMessage(),
                            result,
                            path
                    )
            );
            case RISK_OTP_REQUIRED -> ResponseEntity.status(HttpStatus.OK).body(
                    ApiResponse.success(
                            "RISK_OTP_REQUIRED",
                            result.getMessage(),
                            result,
                            path
                    )
            );
            default -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                    ApiResponse.error(
                            "LOGIN_FAILED",
                            result.getMessage(),
                            path
                    )
            );
        };
    }



//    @PostMapping("/refresh")
//    public ResponseEntity<ApiResponse<AuthResponse>> verifyRefreshToken(
//            @Valid @RequestBody RefreshTokenRequest refreshTokenRequest,
//            HttpServletRequest request) {
//
//        log.info("AuthController.verifyRefreshToken(): Started");
//        AuthResponse response = authService.refreshToken(refreshTokenRequest);
//        log.info("AuthController.verifyRefreshToken(): Finished");
//
//        ApiResponse<AuthResponse> body = ApiResponse.success(
//                "TOKEN_REFRESHED",
//                response.getMessage(),
//                response,
//                request.getRequestURI()
//        );
//        return ResponseEntity.ok(body);
//    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<?>> refreshToken(
            @Valid @RequestBody RefreshTokenRequest request,
            HttpServletRequest httpRequest
    ) {
        String path = httpRequest.getRequestURI();

        AuthenticationResult result =
                refreshTokenOrchestrator.refresh(request.getRefreshToken());

        return ResponseEntity.ok(
                ApiResponse.success(
                        "TOKEN_REFRESHED",
                        result.getMessage(),
                        result,
                        path
                )
        );
    }


//    @PostMapping("/forgot-password")
//    public ResponseEntity<ApiResponse<Void>> forgotPassword(
//            @Valid @RequestBody ForgotPasswordRequest req,
//            HttpServletRequest request) {
//
//        log.info("AuthController.forgotPassword(): Started for email={}", req.getEmail());
//        authService.forgotPassword(req.getEmail());
//        log.info("AuthController.forgotPassword(): Finished for email={}", req.getEmail());
//
//        ApiResponse<Void> body = ApiResponse.success(
//                "PASSWORD_RESET_LINK_SENT",
//                "Password reset link sent to email",
//                null,
//                request.getRequestURI()
//        );
//        return ResponseEntity.ok(body);
//    }

    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponse<?>> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest req,
            HttpServletRequest request
    ) {
        ForgotPasswordResult result =
                forgotPasswordOrchestrator.requestReset(req.getEmail());

        String path = request.getRequestURI();

        return switch (result.getOutcome()) {

            case PASSWORD_RESET -> ResponseEntity.ok(
                    ApiResponse.success(
                            "PASSWORD_RESET_LINK_SENT",
                            result.getMessage(),
                            result,
                            path
                    )
            );

            default -> ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    ApiResponse.error(
                            "PASSWORD_RESET_FAILED",
                            result.getMessage(),
                            path
                    )
            );
        };
    }


//    @PostMapping("/reset-password")
//    public ResponseEntity<ApiResponse<Void>> resetPassword(
//            @Valid @RequestBody ResetPasswordRequest resetPasswordRequest,
//            HttpServletRequest request) {
//
//        log.info("AuthController.resetPassword(): Started");
//        authService.resetPassword(resetPasswordRequest);
//        log.info("AuthController.resetPassword(): Finished");
//
//        ApiResponse<Void> body = ApiResponse.success(
//                "PASSWORD_RESET_SUCCESS",
//                "Password updated successfully",
//                null,
//                request.getRequestURI()
//        );
//        return ResponseEntity.ok(body);
//    }

    @PostMapping("/reset-password")
    public ResponseEntity<ApiResponse<Void>> resetPassword(
            @Valid @RequestBody ResetPasswordRequest request,
            HttpServletRequest httpRequest
    ) {
        resetPasswordOrchestrator.reset(request);

        return ResponseEntity.ok(
                ApiResponse.success(
                        "PASSWORD_RESET_SUCCESS",
                        "Password updated successfully",
                        null,
                        httpRequest.getRequestURI()
                )
        );
    }


//    @GetMapping("/me")
//    public ResponseEntity<ApiResponse<UserDetailsResponse>> fetchUserDetails(
//            HttpServletRequest request) {
//
//        log.info("AuthController.fetchUserDetails(): Started");
//        String token = jwtUtil.resolveToken(request);
//        UserDetailsResponse response = authService.userDetailsFromAccessToken(token);
//        log.info("AuthController.fetchUserDetails(): Finished for email={}", response.getEmail());
//
//        ApiResponse<UserDetailsResponse> body = ApiResponse.success(
//                "USER_DETAILS_FETCHED",
//                "User details fetched successfully",
//                response,
//                request.getRequestURI()
//        );
//        return ResponseEntity.ok(body);
//    }

    @GetMapping("/me")
    public ResponseEntity<ApiResponse<UserDetailsResponse>> fetchUserDetails(
            HttpServletRequest request) {

        String token = jwtUtil.resolveToken(request);

        UserDetailsResponse response =
                userContextOrchestrator.getCurrentUser(token);

        return ResponseEntity.ok(
                ApiResponse.success(
                        "USER_DETAILS_FETCHED",
                        "User details fetched successfully",
                        response,
                        request.getRequestURI()
                )
        );
    }

//    @PostMapping("/logout")
//    public ResponseEntity<ApiResponse<Void>> logout(
//            @RequestBody LogoutRequest requestBody,
//            HttpServletRequest request) {
//
//        log.info("AuthController.logout(): Started");
//
//        authService.logout(requestBody.getAccessToken(), requestBody.getRefreshToken());
//
//        log.info("AuthController.logout(): Finished");
//
//        ApiResponse<Void> body = ApiResponse.success(
//                "LOGOUT_SUCCESS",
//                "Logged out successfully.",
//                null,
//                request.getRequestURI()
//        );
//
//        return ResponseEntity.ok(body);
//    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(
            @RequestBody LogoutRequest requestBody,
            HttpServletRequest request) {

        log.info("AuthController.logout(): started");

        logoutOrchestrator.logout(
                requestBody.getAccessToken(),
                requestBody.getRefreshToken()
        );

        log.info("AuthController.logout(): finished");

        return ResponseEntity.ok(
                ApiResponse.success(
                        "LOGOUT_SUCCESS",
                        "Logged out successfully",
                        null,
                        request.getRequestURI()
                )
        );
    }


//    @PostMapping("/link-oauth")
//    public ResponseEntity<ApiResponse<Void>> linkOAuth(
//            @RequestBody LinkOAuthRequest req,
//            HttpServletRequest request) {
//
//        log.info("AuthController.linkOAuth(): Started");
//        authService.linkOAuthAccount(req);
//        log.info("AuthController.linkOAuth(): Finished");
//
//        ApiResponse<Void> body = ApiResponse.success(
//                "OAUTH_LINKED",
//                "OAuth account linked successfully",
//                null,
//                request.getRequestURI()
//        );
//        return ResponseEntity.ok(body);
//    }

    @PostMapping("/link-oauth")
    public ResponseEntity<ApiResponse<Void>> linkOAuth(
            @RequestBody LinkOAuthRequest request,
            HttpServletRequest httpRequest) {

        log.info("AuthController.linkOAuth(): started");

        linkOAuthOrchestrator.link(request);

        log.info("AuthController.linkOAuth(): finished");

        return ResponseEntity.ok(
                ApiResponse.success(
                        "OAUTH_LINKED",
                        "OAuth account linked successfully",
                        null,
                        httpRequest.getRequestURI()
                )
        );
    }


//    @PostMapping("/change-password")
//    @PreAuthorize("hasAnyRole('USER','ADMIN')")
//    public ResponseEntity<ApiResponse<AuthResponse>> changePassword(@RequestBody @Valid ChangePasswordRequest changePasswordRequest,
//                                                      HttpServletRequest request){
//        log.info("AuthController.changePassword(): started");
//        String token = jwtUtil.resolveToken(request);
//        AuthResponse response = authService.changePassword(token, changePasswordRequest.getOldPassword(),changePasswordRequest.getNewPassword());
//        log.info("AuthController.changePassword(): finished");
//        ApiResponse<AuthResponse> body = ApiResponse.success(
//                "PASSWORD_CHANGED",
//                response.getMessage(),
//                response,
//                request.getRequestURI()
//        );
//        return ResponseEntity.ok(body);
//    }

    @PostMapping("/change-password")
    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    public ResponseEntity<ApiResponse<?>> changePassword(
            @Valid @RequestBody ChangePasswordRequest request,
            HttpServletRequest httpRequest
    ) {
        log.info("AuthController.changePassword(): started");

        String token = jwtUtil.resolveToken(httpRequest);
        String path = httpRequest.getRequestURI();

        AuthenticationResult result =
                changePasswordOrchestrator.changePassword(token, request);

        return ResponseEntity.ok(
                ApiResponse.success(
                        "PASSWORD_CHANGED",
                        result.getMessage(),
                        result,
                        path
                )
        );
    }


    @PutMapping("/update-profile")
    public ResponseEntity<ApiResponse<UserDetailsResponse>> updateProfile(
            @RequestBody @Valid UpdateProfileRequest updateProfileRequest,
            HttpServletRequest request) {

        // 1. Extract token from header
        // 2. Call service
        // 3. Wrap response in ApiResponse

        return null;
    }

//    @PostMapping("verify-mfa")
//    public ResponseEntity<ApiResponse<AuthResponse>> verifyMfaOtp(@RequestBody @Valid MfaTokenVerifyRequest mfaTokenVerifyRequest, HttpServletRequest request){
//        log.info("AuthController.verifyMfaOtp(): started");
//        String ip = request.getHeader("X-Forwarded-For");
//        if (ip == null) ip = request.getRemoteAddr();           //Fetching ip
//        String userAgent = request.getHeader("User-Agent");
//        //fetching browser/device info
//        AuthResponse response = authService.verifyOtp(mfaTokenVerifyRequest, ip, userAgent);
//        log.info("AuthController.verifyMfaOtp(): finished");
//        ApiResponse<AuthResponse> body = ApiResponse.success(
//                "MFA_OTP_VERIFIED",
//                response.getMessage(),
//                response,
//                request.getRequestURI()
//        );
//        return ResponseEntity.ok(body);
//    }

    @PostMapping("/otp/verify")
    public ResponseEntity<ApiResponse<?>> verifyOtp(
            @Valid @RequestBody OtpVerifyRequest request,
            HttpServletRequest httpRequest
    ) {
        String ip = httpRequest.getHeader("X-Forwarded-For");
        if (ip == null) ip = httpRequest.getRemoteAddr();
        String ua = httpRequest.getHeader("User-Agent");

        AuthenticationResult result =
                verifyOtpOrchestrator.verify(request, ip, ua);

        String path = httpRequest.getRequestURI();

        return switch (result.getOutcome()) {

            case SUCCESS -> ResponseEntity.ok(
                    ApiResponse.success(
                            "OTP_VERIFIED",
                            result.getMessage(),
                            result,
                            path
                    )
            );

            default -> ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    ApiResponse.error(
                            "OTP_VERIFICATION_FAILED",
                            result.getMessage(),
                            path
                    )
            );
        };
    }

    @PostMapping("/otp/resend")
    public ResponseEntity<ApiResponse<Void>> resendOtp(
            @Valid @RequestBody OtpResendRequest request,
            HttpServletRequest httpRequest
    ) {
        resendOtpOrchestrator.resend(request);

        return ResponseEntity.ok(
                ApiResponse.success(
                        "OTP_RESENT",
                        "OTP resent successfully",
                        null,
                        httpRequest.getRequestURI()
                )
        );
    }



    @GetMapping("/me/devices")
    public ResponseEntity<ApiResponse<List<TrustedDeviceResponse>>> getMyTrustedDevices() {
        Long userId = authUtil.getCurrentUserId();
        List<TrustedDeviceResponse> devices = trustedDeviceService.getTrustedDevices(userId);

        return ResponseEntity.ok(ApiResponse.success(
                "DEVICES_FETCHED",
                "Trusted devices fetched successfully",
                devices,
                "/api/auth/me/devices"
        ));
    }

    @DeleteMapping("/me/devices/{id}")
    public ResponseEntity<ApiResponse<Void>> removeDevice(@PathVariable Long id) {
        Long userId = authUtil.getCurrentUserId();
        trustedDeviceService.removeDevice(userId, id);

        return ResponseEntity.ok(ApiResponse.success(
                "DEVICE_REMOVED",
                "Device removed successfully",
                null,
                "/api/auth/me/devices/" + id
        ));
    }

    @PostMapping("/me/devices/keep-current")
    public ResponseEntity<ApiResponse<Void>> removeOtherDevices(HttpServletRequest request) {

        Long userId = authUtil.getCurrentUserId();
        String userAgent = request.getHeader("User-Agent");

        DeviceInfo deviceInfo = UserAgentParser.parse(userAgent);
        String signature = deviceInfo.getSignature();

        trustedDeviceService.removeAllExceptCurrent(userId, signature);

        ApiResponse<Void> body = ApiResponse.success(
                "TRUSTED_DEVICES_UPDATED",
                "All other trusted devices have been removed. Only the current device remains trusted.",
                null,
                request.getRequestURI()
        );

        return ResponseEntity.ok(body);
    }
}

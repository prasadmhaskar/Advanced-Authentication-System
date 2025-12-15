package com.pnm.auth.controller;

import com.pnm.auth.dto.result.DeviceInfoResult;
import com.pnm.auth.dto.request.*;
import com.pnm.auth.dto.response.ApiResponse;
import com.pnm.auth.dto.response.DeviceTrustResponse;
import com.pnm.auth.dto.response.UserDetailsResponse;
import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.dto.result.EmailVerificationResult;
import com.pnm.auth.dto.result.ForgotPasswordResult;
import com.pnm.auth.dto.result.RegistrationResult;
import com.pnm.auth.orchestrator.auth.*;
import com.pnm.auth.service.device.DeviceTrustService;
import com.pnm.auth.util.JwtUtil;
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

    private final JwtUtil jwtUtil;
    private final DeviceTrustService deviceTrustService;
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


    @PostMapping("/register")
    public ResponseEntity<ApiResponse<?>> register(@Valid @RequestBody RegisterRequest request,
            HttpServletRequest httpRequest) {

        log.info("AuthController.register(): started for email={}", request.getEmail());

        RegistrationResult result =
                registerOrchestrator.register(request);

        String path = httpRequest.getRequestURI();

        log.info("AuthController.finished(): started for email={}", request.getEmail());

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

        //Keeping empty for the future implementations -currently there is only one field(fullName) that can be updated

        return null;
    }


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
    public ResponseEntity<ApiResponse<List<DeviceTrustResponse>>> getMyTrustedDevices() {
        Long userId = authUtil.getCurrentUserId();
        List<DeviceTrustResponse> devices = deviceTrustService.getTrustedDevices(userId);

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
        deviceTrustService.removeDevice(userId, id);

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

        DeviceInfoResult deviceInfoResult = UserAgentParser.parse(userAgent);
        String signature = deviceInfoResult.getSignature();

        deviceTrustService.removeAllExceptCurrent(userId, signature);

        ApiResponse<Void> body = ApiResponse.success(
                "TRUSTED_DEVICES_UPDATED",
                "All other trusted devices have been removed. Only the current device remains trusted.",
                null,
                request.getRequestURI()
        );

        return ResponseEntity.ok(body);
    }
}

package com.pnm.auth.controller;

import com.pnm.auth.dto.response.ResendOtpResponse;
import com.pnm.auth.dto.result.*;
import com.pnm.auth.dto.request.*;
import com.pnm.auth.dto.response.ApiResponse;
import com.pnm.auth.dto.response.DeviceTrustResponse;
import com.pnm.auth.dto.response.UserDetailsResponse;
import com.pnm.auth.orchestrator.auth.*;
import com.pnm.auth.service.device.DeviceTrustService;
import com.pnm.auth.service.impl.user.UserDetailsImpl;
import com.pnm.auth.util.JwtUtil;
import com.pnm.auth.util.AuthUtil;
import com.pnm.auth.util.UserAgentParser;
import com.sun.security.auth.UserPrincipal;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

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
    private final ResendVerificationOrchestrator resendVerificationOrchestrator;
    private final RegisterOrchestrator registerOrchestrator;
    private final VerifyEmailOrchestrator verifyEmailOrchestrator;
    private final ForgotPasswordOrchestrator forgotPasswordOrchestrator;
    private final ResetPasswordOrchestrator resetPasswordOrchestrator;
    private final RefreshTokenOrchestrator refreshTokenOrchestrator;
    private final UserContextOrchestrator userContextOrchestrator;
    private final LogoutOrchestrator logoutOrchestrator;
    private final LinkOAuthOrchestrator linkOAuthOrchestrator;
    private final ChangePasswordOrchestrator changePasswordOrchestrator;
    private final AccountDeleteOrchestrator accountDeleteOrchestrator;


    @PostMapping("/register")
    public ResponseEntity<ApiResponse<?>> register(@Valid @RequestBody RegisterRequest request,
                                                   HttpServletRequest httpRequest)
    {
        log.info("AuthController.register(): started for email={}", request.getEmail());

        // Extract IP + User-Agent
        String ip = httpRequest.getHeader("X-Forwarded-For");
        if (ip == null) ip = httpRequest.getRemoteAddr();
        String ua = httpRequest.getHeader("User-Agent");

        RegistrationResult result = registerOrchestrator.register(request, ip, ua);

        String path = httpRequest.getRequestURI();

        log.info("AuthController.finished(): finished for email={}", request.getEmail());

        return switch (result.getOutcome()) {

            case REGISTERED -> {
                if (result.getEmailSent()) {
                    yield ResponseEntity.status(HttpStatus.CREATED).body(
                            ApiResponse.success("USER_REGISTERED", "Registration successful. Email verification link is sent successfully.", result, path));
                } else {
                    yield ResponseEntity.status(HttpStatus.CREATED).body(
                            ApiResponse.success("USER_REGISTERED", "Registration successful! Your verification email is on its way.", result, path));
                }
            }

            case LINK_REQUIRED -> ResponseEntity.status(HttpStatus.CONFLICT).body(
                    ApiResponse.errorWithMeta(
                            "ACCOUNT_LINK_REQUIRED",
                            "This email is already registered. Do you want to link accounts?",
                            path,
                            Map.of(
                                    "email", result.getEmail(),
                                    "existingProvider", result.getExistingProvider().name(),
                                    "attemptedProvider", result.getAttemptedProvider().name(),
                                    "nextAction", result.getNextAction().name(),
                                        "linkToken", result.getLinkToken()
                            )
                    ));

            default -> ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    ApiResponse.error(
                            "REGISTRATION_FAILED",
                            "Registration failed",
                            path
                    )
            );
        };
    }


    @GetMapping("/verify")
    public ResponseEntity<ApiResponse<?>> verifyEmail(@RequestParam("token") String token, HttpServletRequest request) {

        log.info("AuthController.verifyEmail(): started for tokenPrefix={}", token.length() > 8 ? token.substring(0, 8) : "short");

        // Extract IP + User-Agent
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null) ip = request.getRemoteAddr();
        String ua = request.getHeader("User-Agent");


        EmailVerificationResult result = verifyEmailOrchestrator.verify(token, ip, ua);

        log.info("AuthController.verifyEmail(): finished for email={}", result.getEmail());

        return ResponseEntity.ok(
                ApiResponse.success(
                        "EMAIL_VERIFIED",
                        "Email verified successfully",
                        result,
                        request.getRequestURI()
                )
        );
    }


    @PostMapping("/verify/resend")
    public ResponseEntity<ApiResponse<?>> resendVerificationEmail(
            @Valid @RequestBody ResendVerificationRequest request,
            HttpServletRequest httpRequest
    ) {
        log.info("AuthController.resendVerificationEmail(): started for email={}", request.getEmail());

        // Extract IP + User-Agent
        String ip = httpRequest.getHeader("X-Forwarded-For");
        if (ip == null) ip = httpRequest.getRemoteAddr();
        String ua = httpRequest.getHeader("User-Agent");

        ResendVerificationResult result = resendVerificationOrchestrator.resend(request.getEmail(), ip, ua);

        String path = httpRequest.getRequestURI();

        log.info("AuthController.resendVerificationEmail(): finished for email={}", request.getEmail());

        return switch (result.getOutcome()) {
            case EMAIL_SENT -> {
                if (result.getEmailSent()) {
                    yield ResponseEntity.ok(
                            ApiResponse.success("VERIFICATION_EMAIL_SENT",
                                    "Verification email sent successfully.", result, path));
                } else {
                    yield ResponseEntity.ok(
                            ApiResponse.success("VERIFICATION_EMAIL_PENDING",
                                    "Your verification email is on its way.", result, path));
                }
            }

            case ALREADY_VERIFIED -> ResponseEntity.ok(
                    ApiResponse.success(
                            "EMAIL_ALREADY_VERIFIED",
                            "Email already verified. Please login.",
                            result,
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
        log.info("AuthController.login(): started for email={}",request.getEmail());

        // Extract IP + User-Agent
        String ip = httpRequest.getHeader("X-Forwarded-For");
        if (ip == null) ip = httpRequest.getRemoteAddr();

        String ua = httpRequest.getHeader("User-Agent");

        AuthenticationResult result = loginOrchestrator.login(request, ip, ua);

        String path = httpRequest.getRequestURI();

        log.info("AuthController.login(): finished for email={}",request.getEmail());

        return switch (result.getOutcome()) {

            case SUCCESS -> ResponseEntity.ok(
                    ApiResponse.success(
                            "LOGIN_SUCCESS",
                            result.getMessage(),
                            result,
                            path
                    )
            );

            case MFA_REQUIRED -> ResponseEntity.ok(
                    ApiResponse.success(
                            "MFA_REQUIRED",
                            result.getMessage(),
                            result,
                            path
                    )
            );

            case RISK_OTP_REQUIRED -> ResponseEntity.ok(
                    ApiResponse.success(
                            "RISK_OTP_REQUIRED",
                            result.getMessage(),
                            result,
                            path
                    )
            );

            case LINK_REQUIRED -> ResponseEntity.status(HttpStatus.CONFLICT).body(
                    ApiResponse.errorWithMeta(
                            "ACCOUNT_LINK_REQUIRED",
                            result.getMessage(),
                            path,
                            Map.of(
                                    "email", result.getEmail(),
                                    "existingProvider", result.getExistingProvider().name(),
                                    "attemptedProvider", result.getAttemptedProvider().name(),
                                    "nextAction", result.getNextAction().name(),
                                    "linkToken", result.getLinkToken()
                            )
                    )
            );

            case PASSWORD_NOT_SET -> ResponseEntity.status(HttpStatus.CONFLICT).body(
                    ApiResponse.errorWithMeta(
                            "PASSWORD_NOT_SET",
                            result.getMessage(),
                            path,
                            Map.of(
                                    "email", result.getEmail(),
                                    "nextAction", result.getNextAction().name()
                            )
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

        // Extract IP + User-Agent
        String ip = httpRequest.getHeader("X-Forwarded-For");
        if (ip == null) ip = httpRequest.getRemoteAddr();

        String ua = httpRequest.getHeader("User-Agent");

        String path = httpRequest.getRequestURI();

        AuthenticationResult result =
                refreshTokenOrchestrator.refresh(request.getRefreshToken(), ip, ua);

        return ResponseEntity.ok(
                ApiResponse.success(
                        "TOKEN_REFRESHED",
                        result.getMessage(),
                        result,
                        path
                )
        );
    }


    //When user is not logged-in. Uses email for getting reset-email link for setting new password.
    //Just sends password reset email on users email
    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponse<?>> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest req,
            HttpServletRequest request
    ) {
        ForgotPasswordResult result =
                forgotPasswordOrchestrator.requestReset(req.getEmail());

        String path = request.getRequestURI();

        return switch (result.getOutcome()) {
            case PASSWORD_RESET -> {
                if (result.getEmailSent()) {
                    yield ResponseEntity.ok(ApiResponse.success("PASSWORD_RESET_LINK_SENT",
                            "If your email is registered, reset link email sent successfully", result, path));
                } else {
                    // Return 202 Accepted: Business logic (token) created, but delivery (email) is pending
                    yield ResponseEntity.status(HttpStatus.ACCEPTED).body(
                            ApiResponse.success("PASSWORD_RESET_PENDING",
                                    "If your email is registered, the request has been processed. Your reset link email is on its way.",
                                    result, path));
                }
            }

            default -> ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    ApiResponse.error(
                            "PASSWORD_RESET_FAILED",
                            result.getMessage(),
                            path
                    )
            );
        };
    }


    //forgotPassword sends this controllers link with token and in this controller actual password change is done.
    @PostMapping("/reset-password")
    public ResponseEntity<ApiResponse<Void>> resetPassword(
            @Valid @RequestBody ResetPasswordRequest request,
            HttpServletRequest httpRequest
    ) {

        // Extract IP + User-Agent
        String ip = httpRequest.getHeader("X-Forwarded-For");
        if (ip == null) ip = httpRequest.getRemoteAddr();

        String ua = httpRequest.getHeader("User-Agent");
        resetPasswordOrchestrator.reset(request, ip, ua);

        return ResponseEntity.ok(
                ApiResponse.success(
                        "PASSWORD_RESET_SUCCESS",
                        "Password updated successfully",
                        null,
                        httpRequest.getRequestURI()
                )
        );
    }


    //When user is logged-in. In profile settings user can change his password after entering old-Password and new-password.
    @PostMapping("/change-password")
    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    public ResponseEntity<ApiResponse<?>> changePassword(
            @Valid @RequestBody ChangePasswordRequest request,
            HttpServletRequest httpRequest
    ) {
        log.info("AuthController.changePassword(): started");

        String token = jwtUtil.resolveToken(httpRequest);
        String path = httpRequest.getRequestURI();

        // Extract IP + User-Agent
        String ip = httpRequest.getHeader("X-Forwarded-For");
        if (ip == null) ip = httpRequest.getRemoteAddr();

        String ua = httpRequest.getHeader("User-Agent");

        AuthenticationResult result =
                changePasswordOrchestrator.changePassword(token, request, ip, ua);

        return ResponseEntity.ok(
                ApiResponse.success(
                        "PASSWORD_CHANGED",
                        result.getMessage(),
                        result,
                        path
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
    public ResponseEntity<ApiResponse<?>> linkOAuth(
            @RequestBody @Valid LinkOAuthRequest request,
            HttpServletRequest httpRequest
    ) {
        log.info("AuthController.linkOAuth(): started");
        AccountLinkResult result = linkOAuthOrchestrator.link(request);

        if (result.getEmailSent()) {
            return ResponseEntity.ok(
                    ApiResponse.success("ACCOUNT_LINKED", result.getMessage(), result, httpRequest.getRequestURI()));
        } else {
            // Return 202 Accepted to signal partial success
            return ResponseEntity.status(HttpStatus.ACCEPTED).body(
                    ApiResponse.success("ACCOUNT_LINKED",
                            result.getMessage(),
                            result, httpRequest.getRequestURI()));
        }
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
    public ResponseEntity<ApiResponse<ResendOtpResponse>> resendOtp(
            @Valid @RequestBody OtpResendRequest request,
            HttpServletRequest httpRequest
    ) {
        ResendOtpResponse resend = resendOtpOrchestrator.resend(request);

        String msg = resend.getEmailSent() ? "OTP sent successfully to your email" : "OTP generated, email is on its way.";

        return ResponseEntity.ok(
                    ApiResponse.success(
                            "OTP_RESENT",
                            msg,
                            resend,
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


    @DeleteMapping("/me/delete-account")
    @Operation(summary = "Delete My Account", description = "Permanently delete account. Requires password for email users.")
    public ResponseEntity<ApiResponse<Void>> deleteMyAccount(
            @AuthenticationPrincipal UserDetailsImpl currentUser,
            @RequestBody(required = false) @Valid DeleteAccountRequest request,
            HttpServletRequest servletRequest
    ) {

        accountDeleteOrchestrator.deleteMyAccount(currentUser.getId(), request != null ? request.getPassword() : null);

        return ResponseEntity.ok(ApiResponse.success(
                "ACCOUNT_DELETED",
                "Your account has been permanently deleted.",
                null,
                servletRequest.getRequestURI()
        ));
    }
}

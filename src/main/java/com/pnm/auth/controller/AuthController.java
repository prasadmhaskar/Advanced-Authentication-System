package com.pnm.auth.controller;

import com.pnm.auth.dto.response.ResendOtpResponse;
import com.pnm.auth.dto.result.*;
import com.pnm.auth.dto.request.*;
import com.pnm.auth.dto.response.ApiResponse;
import com.pnm.auth.dto.response.DeviceTrustResponse;
import com.pnm.auth.dto.response.UserDetailsResponse;
import com.pnm.auth.orchestrator.auth.*;
import com.pnm.auth.service.UserContextService;
import com.pnm.auth.service.device.DeviceTrustService;
import com.pnm.auth.web.context.RequestContext;
import com.pnm.auth.web.filter.RequestContextFilter;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final LoginOrchestrator loginOrchestrator;
    private final VerifyOtpOrchestrator verifyOtpOrchestrator;
    private final ResendOtpOrchestrator resendOtpOrchestrator;
    private final ResendVerificationOrchestrator resendVerificationOrchestrator;
    private final RegisterOrchestrator registerOrchestrator;
    private final VerifyEmailOrchestrator verifyEmailOrchestrator;
    private final ForgotPasswordOrchestrator forgotPasswordOrchestrator;
    private final RefreshTokenOrchestrator refreshTokenOrchestrator;
    private final LinkOAuthOrchestrator linkOAuthOrchestrator;
    private final DeviceTrustService deviceTrustService;
    private final UserContextService userContextService;
    private final ResetPasswordOrchestrator resetPasswordOrchestrator;
    private final ChangePasswordOrchestrator changePasswordOrchestrator;
    private final LogoutOrchestrator logoutOrchestrator;
    private final DeleteAccountOrchestrator deleteAccountOrchestrator;


    @PostMapping("/register")
    public ResponseEntity<ApiResponse<?>> register(@Valid @RequestBody RegisterRequest request,
                                                   HttpServletRequest httpServletRequest)
    {
        RequestContext ctx = (RequestContext) httpServletRequest.getAttribute(RequestContextFilter.REQUEST_CONTEXT_ATTR);

        log.info("AuthController.register(): started ip={} and email={}",ctx.ip(), request.getEmail());

        RegistrationResult result = registerOrchestrator.register(request, ctx);

        log.info("AuthController.register(): finished ip={} and email={}",ctx.ip(), request.getEmail());

        return ResponseEntity.status(HttpStatus.CREATED).body(
                            ApiResponse.success(
                                    "USER_REGISTERED",
                                    "Registration successful. A verification email has been sent to your email address.",
                                    result,
                                    ctx.path()));

    }


    @GetMapping("/verify")
    public ResponseEntity<ApiResponse<?>> verifyEmail(@RequestParam("token") String token, HttpServletRequest httpServletRequest) {

        RequestContext ctx = (RequestContext) httpServletRequest.getAttribute(RequestContextFilter.REQUEST_CONTEXT_ATTR);

        log.info("AuthController.verifyEmail(): started ip={}", ctx.ip());

        EmailVerificationResult result = verifyEmailOrchestrator.verify(token, ctx);

        log.info("AuthController.verifyEmail(): finished ip={} and email={}", ctx.ip(), result.getEmail());

        return ResponseEntity.ok(
                ApiResponse.success(
                        "EMAIL_VERIFIED",
                        "Email verified successfully",
                        result,
                        ctx.path()
                )
        );
    }


    @PostMapping("/verify/resend")
    public ResponseEntity<ApiResponse<?>> resendVerificationEmail(
            @Valid @RequestBody ResendVerificationRequest request,
            HttpServletRequest httpServletRequest
    ) {
        RequestContext ctx = (RequestContext) httpServletRequest.getAttribute(RequestContextFilter.REQUEST_CONTEXT_ATTR);

        log.info("AuthController.resendVerificationEmail(): started ip={} and email={}", ctx.ip(), request.getEmail());

        ResendVerificationResult result = resendVerificationOrchestrator.resend(request.getEmail(), ctx);

        log.info("AuthController.resendVerificationEmail(): finished ip={} and email={}", ctx.ip(), request.getEmail());

        return switch (result.getOutcome()) {
            case EMAIL_SENT -> ResponseEntity.ok(
                            ApiResponse.success("VERIFICATION_EMAIL_SENT",
                                    "A verification email has been sent to your email address.",
                                    result,
                                    ctx.path()));

            case ALREADY_VERIFIED -> ResponseEntity.ok(
                    ApiResponse.success(
                            "EMAIL_ALREADY_VERIFIED",
                            "Email already verified. Please login.",
                            result,
                            ctx.path()
                    ));
        };
    }


    @PostMapping("/login")
    public ResponseEntity<ApiResponse<?>> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpServletRequest
    ) {
        RequestContext ctx = (RequestContext) httpServletRequest.getAttribute(RequestContextFilter.REQUEST_CONTEXT_ATTR);

        log.info("AuthController.login(): started ip={} and email={}", ctx.ip(), request.getEmail());

        AuthenticationResult result = loginOrchestrator.login(request, ctx);

        log.info("AuthController.login(): finished ip={} and email={}", ctx.ip(), request.getEmail());

        return switch (result.getOutcome()) {

            case SUCCESS -> ResponseEntity.ok(
                    ApiResponse.success(
                            "LOGIN_SUCCESS",
                            result.getMessage(),
                            result,
                            ctx.path()
                    )
            );

            case MFA_REQUIRED -> ResponseEntity.ok(
                    ApiResponse.success(
                            "MFA_REQUIRED",
                            result.getMessage(),
                            result,
                            ctx.path()
                    )
            );

            case RISK_OTP_REQUIRED -> ResponseEntity.ok(
                    ApiResponse.success(
                            "RISK_OTP_REQUIRED",
                            result.getMessage(),
                            result,
                            ctx.path()
                    )
            );

            case PASSWORD_NOT_SET -> ResponseEntity.status(HttpStatus.CONFLICT).body(
                    ApiResponse.errorWithMeta(
                            "PASSWORD_NOT_SET",
                            result.getMessage(),
                            ctx.path(),
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
                            ctx.path()
                    )
            );
        };
    }



    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<?>> refreshToken(
            @Valid @RequestBody RefreshTokenRequest request,
            HttpServletRequest httpServletRequest
    ) {
        RequestContext ctx = (RequestContext) httpServletRequest.getAttribute(RequestContextFilter.REQUEST_CONTEXT_ATTR);

        log.info("AuthController.refreshToken(): started ip={}", ctx.ip());

        AuthenticationResult result = refreshTokenOrchestrator.refresh(request.getRefreshToken(), ctx);

        log.info("AuthController.refreshToken(): finished ip={}", ctx.ip());

        return ResponseEntity.ok(
                ApiResponse.success(
                        "TOKEN_REFRESHED",
                        result.getMessage(),
                        result,
                        ctx.path()
                )
        );
    }


    //When user is not logged-in. Uses email for getting reset-email link for setting new password.
    //Just sends password reset email on users email
    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponse<?>> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request,
            HttpServletRequest httpServletRequest
    ) {

        RequestContext ctx = (RequestContext) httpServletRequest.getAttribute(RequestContextFilter.REQUEST_CONTEXT_ATTR);

        log.info("AuthController.forgotPassword(): started ip={} and email={}", ctx.ip(), request.getEmail());

        ForgotPasswordResult result = forgotPasswordOrchestrator.requestReset(request.getEmail(), ctx);

        log.info("AuthController.forgotPassword(): finished ip={} and email={}", ctx.ip(), request.getEmail());

        return ResponseEntity.ok(
                ApiResponse.success(
                        "PASSWORD_RESET_EMAIL_SENT",
                        "If your email is registered, password reset link has been dispatched to your email address.",
                        result,
                        ctx.path()));

        }



    //forgotPassword sends this controller link with token, and in this controller actual password change is done.
    @PostMapping("/reset-password")
    public ResponseEntity<ApiResponse<Void>> resetPassword(
            @Valid @RequestBody ResetPasswordRequest request,
            HttpServletRequest httpServletRequest
    ) {
        RequestContext ctx = (RequestContext) httpServletRequest.getAttribute(RequestContextFilter.REQUEST_CONTEXT_ATTR);

        log.info("AuthController.resetPassword(): started ip={}", ctx.ip());

        resetPasswordOrchestrator.resetPassword(request, ctx);

        log.info("AuthController.resetPassword(): finished ip={}", ctx.ip());

        return ResponseEntity.ok(
                ApiResponse.success(
                        "PASSWORD_RESET_SUCCESS",
                        "Password updated successfully",
                        null,
                        ctx.path()
                )
        );
    }


    //When user is logged-in. In profile settings user can change his password after entering old-Password and new-password.
    @PostMapping("/change-password")
    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    public ResponseEntity<ApiResponse<?>> changePassword(
            @Valid @RequestBody ChangePasswordRequest request,
            HttpServletRequest httpServletRequest
    ) {
        RequestContext ctx = (RequestContext) httpServletRequest.getAttribute(RequestContextFilter.REQUEST_CONTEXT_ATTR);

        log.info("AuthController.changePassword(): started ip={}", ctx.ip());

        AuthenticationResult result = changePasswordOrchestrator.changePassword(request, ctx);

        log.info("AuthController.changePassword(): finished ip={}", ctx.ip());

        return ResponseEntity.ok(
                ApiResponse.success(
                        "PASSWORD_CHANGED",
                        result.getMessage(),
                        result,
                        ctx.path()
                )
        );
    }


    @GetMapping("/me")
    public ResponseEntity<ApiResponse<UserDetailsResponse>> fetchUserDetails(HttpServletRequest httpServletRequest) {

        RequestContext ctx = (RequestContext) httpServletRequest.getAttribute(RequestContextFilter.REQUEST_CONTEXT_ATTR);

        log.info("AuthController.fetchUserDetails(): started ip={}", ctx.ip());

        UserDetailsResponse result = userContextService.getCurrentUser(ctx);

        log.info("AuthController.fetchUserDetails(): finished ip={}", ctx.ip());

        return ResponseEntity.ok(
                ApiResponse.success(
                        "USER_DETAILS_FETCHED",
                        "User details fetched successfully",
                        result,
                        ctx.path()
                )
        );
    }


    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout( @RequestBody(required = false) LogoutRequest request, HttpServletRequest httpServletRequest) {

        RequestContext ctx = (RequestContext) httpServletRequest.getAttribute(RequestContextFilter.REQUEST_CONTEXT_ATTR);

        log.info("AuthController.logout(): started ip={}", ctx.ip());

        logoutOrchestrator.logout(request, httpServletRequest, ctx);

        log.info("AuthController.logout(): finished ip={}", ctx.ip());

        return ResponseEntity.ok(
                ApiResponse.success(
                        "LOGOUT_SUCCESS",
                        "Logged out successfully",
                        null,
                        ctx.path()
                )
        );
    }


    @PostMapping("/link-oauth")
    public ResponseEntity<ApiResponse<?>> linkOAuth(
            @RequestBody @Valid LinkOAuthRequest request,
            HttpServletRequest httpServletRequest
    ) {
        RequestContext ctx = (RequestContext) httpServletRequest.getAttribute(RequestContextFilter.REQUEST_CONTEXT_ATTR);

        log.info("AuthController.linkOAuth(): started ip={}", ctx.ip());

        AccountLinkResult result = linkOAuthOrchestrator.link(request, ctx);

        log.info("AuthController.linkOAuth(): finished ip={}", ctx.ip());

            return ResponseEntity.ok(
                    ApiResponse.success(
                            "ACCOUNT_LINKED",
                            result.getMessage(),
                            result,
                            ctx.path()));
    }


    @PutMapping("/update-profile")
    public ResponseEntity<ApiResponse<UserDetailsResponse>> updateProfile(
            @RequestBody @Valid UpdateProfileRequest updateProfileRequest,
            HttpServletRequest httpServletRequest) {

        //Keeping empty for the future implementations -currently there is only one field(fullName) that can be updated

        return null;
    }


    @PostMapping("/otp/verify")
    public ResponseEntity<ApiResponse<?>> verifyOtp(
            @Valid @RequestBody OtpVerifyRequest request,
            HttpServletRequest httpServletRequest
    ) {
        RequestContext ctx = (RequestContext) httpServletRequest.getAttribute(RequestContextFilter.REQUEST_CONTEXT_ATTR);

        log.info("AuthController.verifyOtp(): started ip={}", ctx.ip());

        AuthenticationResult result = verifyOtpOrchestrator.verify(request, ctx);

        log.info("AuthController.verifyOtp(): finished ip={}", ctx.ip());

        return switch (result.getOutcome()) {

            case SUCCESS -> ResponseEntity.ok(
                    ApiResponse.success(
                            "OTP_VERIFIED",
                            result.getMessage(),
                            result,
                            ctx.path()
                    )
            );

            default -> ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    ApiResponse.error(
                            "OTP_VERIFICATION_FAILED",
                            result.getMessage(),
                            ctx.path()
                    )
            );
        };
    }


    @PostMapping("/otp/resend")
    public ResponseEntity<ApiResponse<ResendOtpResponse>> resendOtp(
            @Valid @RequestBody OtpResendRequest request,
            HttpServletRequest httpServletRequest
    ) {
        RequestContext ctx = (RequestContext) httpServletRequest.getAttribute(RequestContextFilter.REQUEST_CONTEXT_ATTR);

        log.info("AuthController.resendOtp(): started ip={}", ctx.ip());

        ResendOtpResponse result = resendOtpOrchestrator.resend(request, ctx);

        log.info("AuthController.resendOtp(): finished ip={}", ctx.ip());

        return ResponseEntity.ok(
                    ApiResponse.success(
                            "OTP_RESENT",
                            "OTP has been sent to your email address.",
                            result,
                            ctx.path()
                    )
            );

    }


    @GetMapping("/me/devices")
    public ResponseEntity<ApiResponse<List<DeviceTrustResponse>>> getMyTrustedDevices(HttpServletRequest httpServletRequest) {

        RequestContext ctx = (RequestContext) httpServletRequest.getAttribute(RequestContextFilter.REQUEST_CONTEXT_ATTR);

        log.info("AuthController.getMyTrustedDevices(): started ip={}", ctx.ip());

        List<DeviceTrustResponse> devices = deviceTrustService.getTrustedDevices(ctx);

        log.info("AuthController.getMyTrustedDevices(): finished ip={}",ctx.ip());

        return ResponseEntity.ok(ApiResponse.success(
                "DEVICES_FETCHED",
                "Trusted devices fetched successfully",
                devices,
                ctx.path()
        ));
    }


    @DeleteMapping("/me/devices/{id}")
    public ResponseEntity<ApiResponse<Void>> removeDevice(@PathVariable Long id, HttpServletRequest httpServletRequest) {

        RequestContext ctx = (RequestContext) httpServletRequest.getAttribute(RequestContextFilter.REQUEST_CONTEXT_ATTR);

        log.info("AuthController.removeDevice(): started ip={}", ctx.ip());

        deviceTrustService.removeDevice(id, ctx);

        log.info("AuthController.removeDevice(): finished ip={}", ctx.ip());

        return ResponseEntity.ok(ApiResponse.success(
                "DEVICE_REMOVED",
                "Device removed successfully",
                null,
                ctx.path()
        ));
    }


    @PostMapping("/me/devices/keep-current")
    public ResponseEntity<ApiResponse<Void>> removeOtherDevices(HttpServletRequest httpServletRequest) {

        RequestContext ctx = (RequestContext) httpServletRequest.getAttribute(RequestContextFilter.REQUEST_CONTEXT_ATTR);

        log.info("AuthController.removeOtherDevices(): started ip={}",ctx.ip());

        deviceTrustService.removeAllExceptCurrent(ctx);

        log.info("AuthController.removeOtherDevices(): finished ip={}",ctx.ip());

        ApiResponse<Void> body = ApiResponse.success(
                "TRUSTED_DEVICES_UPDATED",
                "All other devices have been logged out. Only the current device remains active.",
                null,
                ctx.path()
        );
        return ResponseEntity.ok(body);
    }


    @DeleteMapping("/me/delete-account")
    @Operation(summary = "Delete My Account", description = "Permanently delete account. Requires password for email users.")
    public ResponseEntity<ApiResponse<Void>> deleteMyAccount(
            @RequestBody @Valid DeleteAccountRequest request,
            HttpServletRequest httpServletRequest
    ) {
        RequestContext ctx = (RequestContext) httpServletRequest.getAttribute(RequestContextFilter.REQUEST_CONTEXT_ATTR);

        log.info("AuthController.deleteMyAccount(): started ip={}", ctx.ip());

        deleteAccountOrchestrator.deleteMyAccount(request,httpServletRequest, ctx);

        log.info("AuthController.deleteMyAccount(): finished ip={}", ctx.ip());

        return ResponseEntity.ok(ApiResponse.success(
                "ACCOUNT_DELETED",
                "Your account has been permanently deleted.",
                null,
                ctx.path()
        ));
    }
}

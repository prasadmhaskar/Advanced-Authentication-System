package com.pnm.auth.exception;

import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import com.pnm.auth.dto.response.ApiResponse;
import com.pnm.auth.dto.response.FieldErrorResponse;
import com.pnm.auth.exception.custom.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import jakarta.servlet.http.HttpServletRequest;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    // ================================================================
    //            VALIDATION ERRORS (400)
    // ================================================================
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Void>> handleValidationErrors(
            MethodArgumentNotValidException ex,
            HttpServletRequest request
    ) {
        log.warn("Validation failed at path={} | errors={}", request.getRequestURI(), ex.getMessage());

        List<FieldErrorResponse> fieldErrors = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(err -> new FieldErrorResponse(err.getField(), err.getDefaultMessage()))
                .toList();

        ApiResponse<Void> body = ApiResponse.validationError(
                "VALIDATION_FAILED",
                request.getRequestURI(),
                fieldErrors
        );

        return ResponseEntity.badRequest().body(body);
    }


    // ================================================================
    //            SECURITY RELATED EXCEPTIONS
    // ================================================================

    // ❌ Wrong password, wrong OTP, login failed
    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<ApiResponse<Void>> handleInvalidCredentials(
            InvalidCredentialsException ex, HttpServletRequest request) {

        log.warn("InvalidCredentialsException at path={}: {}", request.getRequestURI(), ex.getMessage());

        ApiResponse<Void> body = ApiResponse.error(
                "INVALID_CREDENTIALS",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
    }

    // ❌ Token invalid, corrupted, not found
    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<ApiResponse<Void>> handleInvalidToken(
            InvalidTokenException ex, HttpServletRequest request) {

        log.warn("InvalidTokenException at path={}: {}", request.getRequestURI(), ex.getMessage());

        ApiResponse<Void> body = ApiResponse.error(
                "INVALID_TOKEN",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
    }

    // 🚫 Account is blocked
    @ExceptionHandler(AccountBlockedException.class)
    public ResponseEntity<ApiResponse<Void>> handleAccountBlocked(
            AccountBlockedException ex, HttpServletRequest request) {

        log.warn("AccountBlockedException at path={}: {}", request.getRequestURI(), ex.getMessage());

        ApiResponse<Void> body = ApiResponse.error(
                "ACCOUNT_BLOCKED",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(body);
    }

    // 🚫 Risk Engine High-Risk: Block login
    @ExceptionHandler(HighRiskLoginException.class)
    public ResponseEntity<ApiResponse<Void>> handleHighRisk(
            HighRiskLoginException ex, HttpServletRequest request) {

        log.error("HighRiskLoginException at path={}: {}", request.getRequestURI(), ex.getMessage());

        ApiResponse<Void> body = ApiResponse.error(
                "HIGH_RISK_LOGIN_BLOCKED",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(body);
    }

    @ExceptionHandler(RiskOtpRequiredException.class)
    public ResponseEntity<ApiResponse<Void>> handleRiskOtpRequired(
            RiskOtpRequiredException ex,HttpServletRequest request) {

        log.warn("RiskOtpRequiredException at path={}: {}", request.getRequestURI(), ex.getMessage());

        Map<String, Object> meta = new HashMap<>();
        meta.put("mfaTokenId", ex.getTokenId());

        ApiResponse<Void> body = ApiResponse.errorWithMeta(
                "RISK_OTP_REQUIRED",
                ex.getMessage(),
                request.getRequestURI(),
                meta
        );

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
    }



    // ================================================================
    //            USER MANAGEMENT EXCEPTIONS
    // ================================================================
    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ApiResponse<Void>> handleUserNotFound(
            UserNotFoundException ex, HttpServletRequest request) {

        log.warn("UserNotFoundException at path={}: {}", request.getRequestURI(), ex.getMessage());

        ApiResponse<Void> body = ApiResponse.error(
                "USER_NOT_FOUND",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(body);
    }

    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<ApiResponse<Void>> handleUserExists(
            UserAlreadyExistsException ex, HttpServletRequest request) {

        log.warn("UserAlreadyExistsException at path={}: {}", request.getRequestURI(), ex.getMessage());

        ApiResponse<Void> body = ApiResponse.error(
                "USER_ALREADY_EXISTS",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }


    // ================================================================
    //            EMAIL / OTP EXCEPTIONS
    // ================================================================
    @ExceptionHandler(EmailSendFailedException.class)
    public ResponseEntity<ApiResponse<Void>> handleEmailSendFailure(
            EmailSendFailedException ex, HttpServletRequest request) {

        log.error("EmailSendFailedException at path={}: {}", request.getRequestURI(), ex.getMessage());

        ApiResponse<Void> body = ApiResponse.error(
                "EMAIL_SEND_FAILED",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }


    // ================================================================
    //            RESOURCE NOT FOUND (404)
    // ================================================================
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiResponse<Void>> handleResourceNotFound(
            ResourceNotFoundException ex, HttpServletRequest request) {

        log.warn("ResourceNotFoundException at path={}: {}", request.getRequestURI(), ex.getMessage());

        ApiResponse<Void> body = ApiResponse.error(
                "RESOURCE_NOT_FOUND",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(body);
    }


    // ================================================================
//                    REGISTRATION EXCEPTIONS
// ================================================================
    @ExceptionHandler(RegistrationFailedException.class)
    public ResponseEntity<ApiResponse<Void>> handleRegistrationFailure(
            RegistrationFailedException ex, HttpServletRequest request) {

        log.error("RegistrationFailedException at path={}: {}", request.getRequestURI(), ex.getMessage());

        ApiResponse<Void> body = ApiResponse.error(
                "REGISTRATION_FAILED",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }


    // ================================================================
//                        LOGIN EXCEPTIONS
// ================================================================
    @ExceptionHandler(LoginFailedException.class)
    public ResponseEntity<ApiResponse<Void>> handleLoginFailure(
            LoginFailedException ex, HttpServletRequest request) {

        log.error("LoginFailedException at path={}: {}", request.getRequestURI(), ex.getMessage());

        ApiResponse<Void> body = ApiResponse.error(
                "LOGIN_FAILED",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
    }


    // ================================================================
//               TOKEN / VERIFICATION / RESET EXCEPTIONS
// ================================================================
    @ExceptionHandler(TokenGenerationException.class)
    public ResponseEntity<ApiResponse<Void>> handleTokenGenerationFailure(
            TokenGenerationException ex, HttpServletRequest request) {

        log.error("TokenGenerationException at path={}: {}", request.getRequestURI(), ex.getMessage());

        ApiResponse<Void> body = ApiResponse.error(
                "TOKEN_GENERATION_FAILED",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }


    // ================================================================
//                       USER UPDATE EXCEPTIONS
// ================================================================
    @ExceptionHandler(UserUpdateException.class)
    public ResponseEntity<ApiResponse<Void>> handleUserUpdateFailure(
            UserUpdateException ex, HttpServletRequest request) {

        log.error("UserUpdateException at path={}: {}", request.getRequestURI(), ex.getMessage());

        ApiResponse<Void> body = ApiResponse.error(
                "USER_UPDATE_FAILED",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }


    // ================================================================
//                    DATABASE OPERATION EXCEPTIONS
// ================================================================
    @ExceptionHandler(DatabaseOperationException.class)
    public ResponseEntity<ApiResponse<Void>> handleDatabaseOperationFailure(
            DatabaseOperationException ex, HttpServletRequest request) {

        log.error("DatabaseOperationException at path={}: {}", request.getRequestURI(), ex.getMessage());

        ApiResponse<Void> body = ApiResponse.error(
                "DATABASE_OPERATION_FAILED",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }


    // ================================================================
//                       OTP GENERATION EXCEPTIONS
// ================================================================
    @ExceptionHandler(OtpGenerationException.class)
    public ResponseEntity<ApiResponse<Void>> handleOtpGenerationFailure(
            OtpGenerationException ex, HttpServletRequest request) {

        log.error("OtpGenerationException at path={}: {}", request.getRequestURI(), ex.getMessage());

        ApiResponse<Void> body = ApiResponse.error(
                "OTP_GENERATION_FAILED",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }

    // ================================================================
//                     PASSWORD RESET EXCEPTIONS
// ================================================================
    @ExceptionHandler(PasswordResetException.class)
    public ResponseEntity<ApiResponse<Void>> handlePasswordResetException(
            PasswordResetException ex,
            HttpServletRequest request
    ) {
        log.error("PasswordResetException at path={}: {}", request.getRequestURI(), ex.getMessage());

        ApiResponse<Void> body = ApiResponse.error(
                "PASSWORD_RESET_FAILED",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }


    // ================================================================
//                     LOGOUT EXCEPTIONS
// ================================================================
    @ExceptionHandler(LogoutFailedException.class)
    public ResponseEntity<ApiResponse<Void>> handleLogoutFailedException(
            LogoutFailedException ex,
            HttpServletRequest request
    ) {
        log.error("LogoutFailedException at path={}: {}", request.getRequestURI(), ex.getMessage());

        ApiResponse<Void> body = ApiResponse.error(
                "LOGOUT_FAILED",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }

    // ================================================================
//                     OAuth link failed EXCEPTIONS
// ================================================================

    @ExceptionHandler(OAuthLinkFailedException.class)
    public ResponseEntity<ApiResponse<Void>> handleOAuthLinkFailed(
            OAuthLinkFailedException ex,
            HttpServletRequest request
    ) {
        log.error("OAuthLinkFailedException at path={}: {}", request.getRequestURI(), ex.getMessage());

        ApiResponse<Void> body = ApiResponse.error(
                "OAUTH_LINK_FAILED",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }


    // ================================================================
//                     Password change EXCEPTIONS
// ================================================================

    @ExceptionHandler(PasswordChangeException.class)
    public ResponseEntity<ApiResponse<Void>> handlePasswordChangeException(
            PasswordChangeException ex,
            HttpServletRequest request
    ) {
        log.error("PasswordChangeException at path={}: {}", request.getRequestURI(), ex.getMessage());

        ApiResponse<Void> body = ApiResponse.error(
                "PASSWORD_CHANGE_FAILED",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }


    // ================================================================
//                     OTP VERIFICATION EXCEPTIONS
// ================================================================
    @ExceptionHandler(OtpVerificationException.class)
    public ResponseEntity<ApiResponse<Void>> handleOtpVerificationException(
            OtpVerificationException ex,
            HttpServletRequest request
    ) {
        log.error("OtpVerificationException at path={}: {}", request.getRequestURI(), ex.getMessage());

        ApiResponse<Void> body = ApiResponse.error(
                "OTP_VERIFICATION_FAILED",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }

    // ================================================================
//                    OAUTH2 LOGIN EXCEPTIONS
// ================================================================
    @ExceptionHandler(OAuth2LoginFailedException.class)
    public ResponseEntity<ApiResponse<Void>> handleOAuth2LoginFailedException(
            OAuth2LoginFailedException ex,
            HttpServletRequest request
    ) {
        log.error("OAuth2LoginFailedException at path={}: {}", request.getRequestURI(), ex.getMessage());

        ApiResponse<Void> body = ApiResponse.error(
                "OAUTH2_LOGIN_FAILED",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }


    @ExceptionHandler(UnrecognizedPropertyException.class)
    public ResponseEntity<ApiResponse<Void>> handleUnknownJsonField(
            UnrecognizedPropertyException ex,
            HttpServletRequest request
    ) {
        return ResponseEntity.badRequest().body(
                ApiResponse.error(
                        "INVALID_REQUEST",
                        "Unrecognized field: " + ex.getPropertyName(),
                        request.getRequestURI()
                )
        );
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiResponse<Void>> handleInvalidJson(
            HttpMessageNotReadableException ex,
            HttpServletRequest request
    ) {
        return ResponseEntity.badRequest().body(
                ApiResponse.error(
                        "INVALID_JSON",
                        "Malformed or invalid JSON request",
                        request.getRequestURI()
                )
        );
    }


    @ExceptionHandler(TooManyRequestsException.class)
    public ResponseEntity<ApiResponse<Void>> handleTooManyRequestsException(
            TooManyRequestsException ex,
            HttpServletRequest request) {

        log.warn("TooManyRequestsException at path={} message={}", request.getRequestURI(), ex.getMessage());

        ApiResponse<Void> body = ApiResponse.error(
                "TOO_MANY_REQUESTS",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(body);
    }


    @ExceptionHandler(EmailNotVerifiedException.class)
    public ResponseEntity<ApiResponse<Void>> handleEmailNotVerified(
            EmailNotVerifiedException ex,
            HttpServletRequest request) {

        log.warn("EmailNotVerifiedException at path={} msg={}", request.getRequestURI(), ex.getMessage());

        ApiResponse<Void> body = ApiResponse.error(
                "EMAIL_NOT_VERIFIED",
                ex.getMessage(),
                request.getRequestURI()
        );
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(body);
    }


    @ExceptionHandler(OAuthPasswordLoginNotAllowedException.class)
    public ResponseEntity<ApiResponse<Void>> handleOAuthPasswordLoginNotAllowed(
            OAuthPasswordLoginNotAllowedException ex,
            HttpServletRequest request) {

        log.warn("OAuthPasswordLoginNotAllowedException at path={} msg={}", request.getRequestURI(), ex.getMessage());

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                ApiResponse.error(
                        "OAUTH_PASSWORD_LOGIN_NOT_ALLOWED",
                        ex.getMessage(),
                        request.getRequestURI()
                )
        );
    }






    // ================================================================
    //            FALLBACK FOR ALL UNHANDLED ERRORS (500)
    // ================================================================
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleGeneral(
            Exception ex, HttpServletRequest request) {

        log.error("Unhandled Exception at path={}", request.getRequestURI(), ex);

        ApiResponse<Void> body = ApiResponse.error(
                "INTERNAL_SERVER_ERROR",
                "Something went wrong",
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }
}


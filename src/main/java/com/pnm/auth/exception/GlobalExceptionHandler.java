package com.pnm.auth.exception;

import com.pnm.auth.dto.response.ApiResponse;
import com.pnm.auth.dto.response.FieldErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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


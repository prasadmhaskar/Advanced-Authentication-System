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

import java.util.List;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    // -----------------------------
    //  VALIDATION ERRORS
    // -----------------------------
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

        ApiResponse<Void> response = ApiResponse.validationError(
                "Validation failed",
                request.getRequestURI(),
                fieldErrors
        );

        return ResponseEntity.badRequest().body(response);
    }

    // -----------------------------
    //  CUSTOM EXCEPTIONS
    // -----------------------------
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

    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<ApiResponse<Void>> handleInvalidToken(
            InvalidTokenException ex, HttpServletRequest request) {

        log.warn("InvalidTokenException at path={}: {}", request.getRequestURI(), ex.getMessage());

        ApiResponse<Void> body = ApiResponse.error(
                "INVALID_TOKEN",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<ApiResponse<Void>> handleInvalidCredentials(
            InvalidCredentialsException ex, HttpServletRequest request) {

        log.warn("InvalidCredentialsException at path={}: {}", request.getRequestURI(), ex.getMessage());

        ApiResponse<Void> body = ApiResponse.error(
                "INVALID_CREDENTIALS",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    @ExceptionHandler(EmailSendFailedException.class)
    public ResponseEntity<ApiResponse<Void>> handleFailedToSendEmail(
            EmailSendFailedException ex, HttpServletRequest request) {

        log.error("EmailSendFailedException at path={}: {}", request.getRequestURI(), ex.getMessage());

        ApiResponse<Void> body = ApiResponse.error(
                "EMAIL_SEND_FAILED",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }

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

    // -----------------------------
    //  GENERIC FALLBACK
    // -----------------------------
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

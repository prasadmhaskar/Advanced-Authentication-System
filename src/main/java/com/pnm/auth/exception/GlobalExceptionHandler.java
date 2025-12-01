package com.pnm.auth.exception;

import com.pnm.auth.dto.response.ApiResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import jakarta.servlet.http.HttpServletRequest;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ApiResponse<Void>> handleUserNotFound(
            UserNotFoundException ex, HttpServletRequest request) {

        log.warn("UserNotFoundException: {} at path={}", ex.getMessage(), request.getRequestURI());
        ApiResponse<Void> body = ApiResponse.error(
                ex.getMessage(),
                "USER_NOT_FOUND",
                request.getRequestURI()
        );
        return new ResponseEntity<>(body, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<ApiResponse<Void>> handleUserExists(
            UserAlreadyExistsException ex, HttpServletRequest request) {

        log.warn("UserAlreadyExistsException: {} at path={}", ex.getMessage(), request.getRequestURI());
        ApiResponse<Void> body = ApiResponse.error(
                ex.getMessage(),
                "USER_ALREADY_EXISTS",
                request.getRequestURI()
        );
        return new ResponseEntity<>(body, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<ApiResponse<Void>> handleInvalidToken(
            InvalidTokenException ex, HttpServletRequest request) {

        log.warn("InvalidTokenException: {} at path={}", ex.getMessage(), request.getRequestURI());
        ApiResponse<Void> body = ApiResponse.error(
                ex.getMessage(),
                "INVALID_TOKEN",
                request.getRequestURI()
        );
        return new ResponseEntity<>(body, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<ApiResponse<Void>> handleInvalidCredentials(
            InvalidCredentialsException ex, HttpServletRequest request) {

        log.warn("InvalidCredentialsException: {} at path={}", ex.getMessage(), request.getRequestURI());
        ApiResponse<Void> body = ApiResponse.error(
                ex.getMessage(),
                "INVALID_CREDENTIALS",
                request.getRequestURI()
        );
        return new ResponseEntity<>(body, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(EmailSendFailedException.class)
    public ResponseEntity<ApiResponse<Void>> handleFailedToSendEmail(
            EmailSendFailedException ex, HttpServletRequest request) {

        log.error("EmailSendFailedException: {} at path={}", ex.getMessage(), request.getRequestURI());
        ApiResponse<Void> body = ApiResponse.error(
                ex.getMessage(),
                "EMAIL_SEND_FAILED",
                request.getRequestURI()
        );
        return new ResponseEntity<>(body, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    // Generic fallback
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleGeneral(
            Exception ex, HttpServletRequest request) {

        log.error("Unhandled exception at path={}", request.getRequestURI(), ex);
        ApiResponse<Void> body = ApiResponse.error(
                "Internal server error",
                "INTERNAL_ERROR",
                request.getRequestURI()
        );
        return new ResponseEntity<>(body, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}

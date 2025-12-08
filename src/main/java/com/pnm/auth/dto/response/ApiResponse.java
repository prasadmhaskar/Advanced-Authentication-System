package com.pnm.auth.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiResponse<T> {

    private boolean success;

    private String code;     // e.g. SUCCESS, USER_CREATED, VALIDATION_FAILED

    private String message;

    private String path;

    private String timestamp;

    private T data;

    private List<FieldErrorResponse> errors; // only for validation errors

    private Map<String, Object> meta; // ⭐ NEW FIELD


    // -----------------------------------------------------
    // SUCCESS (no meta)
    // -----------------------------------------------------
    public static <T> ApiResponse<T> success(String code, String message, T data, String path) {
        return ApiResponse.<T>builder()
                .success(true)
                .code(code)
                .message(message)
                .data(data)
                .path(path)
                .timestamp(Instant.now().toString())
                .build();
    }

    // -----------------------------------------------------
    // SUCCESS with meta
    // -----------------------------------------------------
    public static <T> ApiResponse<T> successWithMeta(
            String code, String message, T data, String path, Map<String, Object> meta) {
        return ApiResponse.<T>builder()
                .success(true)
                .code(code)
                .message(message)
                .data(data)
                .path(path)
                .timestamp(Instant.now().toString())
                .meta(meta)
                .build();
    }


    // -----------------------------------------------------
    // ERROR (no meta)
    // -----------------------------------------------------
    public static <T> ApiResponse<T> error(String code, String message, String path) {
        return ApiResponse.<T>builder()
                .success(false)
                .code(code)
                .message(message)
                .path(path)
                .timestamp(Instant.now().toString())
                .build();
    }

    // -----------------------------------------------------
    // ERROR with meta (⭐ Risk-based OTP will use this)
    // -----------------------------------------------------
    public static <T> ApiResponse<T> errorWithMeta(
            String code,
            String message,
            String path,
            Map<String, Object> meta
    ) {
        return ApiResponse.<T>builder()
                .success(false)
                .code(code)
                .message(message)
                .path(path)
                .timestamp(Instant.now().toString())
                .meta(meta)
                .build();
    }


    // -----------------------------------------------------
    // VALIDATION ERROR
    // -----------------------------------------------------
    public static <T> ApiResponse<T> validationError(
            String message,
            String path,
            List<FieldErrorResponse> errors
    ) {
        return ApiResponse.<T>builder()
                .success(false)
                .code("VALIDATION_FAILED")
                .message(message)
                .path(path)
                .timestamp(Instant.now().toString())
                .errors(errors)
                .build();
    }
}



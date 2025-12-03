package com.pnm.auth.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.*;

import java.time.Instant;
import java.util.List;

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

    private List<FieldErrorResponse> errors; // only for validation cases

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

    public static <T> ApiResponse<T> error(String code, String message, String path) {
        return ApiResponse.<T>builder()
                .success(false)
                .code(code)
                .message(message)
                .path(path)
                .timestamp(Instant.now().toString())
                .build();
    }

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


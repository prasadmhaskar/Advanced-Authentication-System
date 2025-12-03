package com.pnm.auth.dto.request;

import lombok.*;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginActivityFilterRequest {

    private String email;
    private String status;  // SUCCESS / FAILED
    private Long userId;

    private LocalDateTime start;
    private LocalDateTime end;
}


package com.pnm.auth.dto.request;

import lombok.Data;

@Data
public class EmailVerificationRequest {
    private String token;
}

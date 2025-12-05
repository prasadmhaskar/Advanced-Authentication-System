package com.pnm.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class RiskOtpVerifyRequest {
    @NotBlank
    private String email;

    @NotBlank
    private String otp;
}

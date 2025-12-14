package com.pnm.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;

@Data
public class OtpVerifyRequest {

    @NotNull
    private Long tokenId;

    @NotBlank
    private String otp;
}


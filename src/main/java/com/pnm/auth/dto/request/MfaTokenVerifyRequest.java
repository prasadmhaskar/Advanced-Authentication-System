package com.pnm.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class MfaTokenVerifyRequest {

    @NotNull
    private Long id;

    @NotBlank
    private String otp;

}

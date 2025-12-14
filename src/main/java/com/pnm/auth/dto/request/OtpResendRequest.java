package com.pnm.auth.dto.request;

import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class OtpResendRequest {

    @NotNull
    private Long tokenId;
}


package com.pnm.auth.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
public class LogoutRequest {
    @Schema(
            description = "If true, logs out from all active sessions. If false, logs out only the current device.",
            example = "false",
            defaultValue = "false"
    )
    private Boolean logoutFromAllDevices = false;
    private String refreshToken;
}


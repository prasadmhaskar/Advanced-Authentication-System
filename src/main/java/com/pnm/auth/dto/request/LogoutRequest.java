package com.pnm.auth.dto.request;

import lombok.Data;

@Data
public class LogoutRequest {
    private Boolean logoutFromAllDevices = false;
    private String refreshToken;
}


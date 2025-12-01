package com.pnm.auth.dto.request;

import lombok.Data;

@Data
public class LogoutRequest {
    private String accessToken;
    private String refreshToken;
}


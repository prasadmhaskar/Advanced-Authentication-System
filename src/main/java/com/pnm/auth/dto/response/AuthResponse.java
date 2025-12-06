package com.pnm.auth.dto.response;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AuthResponse {
    private String type;
    private String message;
    private String accessToken;
    private String refreshToken;
    private Long mfaTokenId;

}

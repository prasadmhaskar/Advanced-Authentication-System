package com.pnm.auth.dto.result;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.dto.response.UserResponse;
import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AuthenticationResult {

    private AuthOutcome outcome;

    private UserResponse user;

    private String accessToken;
    private String refreshToken;

    private Long otpTokenId; // used for MFA or risk OTP

    private String message;
}



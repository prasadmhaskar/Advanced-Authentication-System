package com.pnm.auth.dto.result;

import com.pnm.auth.entity.User;
import com.pnm.auth.enums.AuthOutcome;
import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AuthenticationResult {

    private AuthOutcome outcome;

    private User user; // only set for success

    private String accessToken;
    private String refreshToken;

    private Long otpTokenId; // used for MFA or risk OTP

    private String message;
}



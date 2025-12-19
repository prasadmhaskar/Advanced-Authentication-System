package com.pnm.auth.dto.result;

import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.domain.enums.NextAction;
import lombok.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class EmailVerificationResult {

    private AuthOutcome outcome;

    private String email;

    private NextAction nextAction;

    private String accessToken;
    private String refreshToken;
}


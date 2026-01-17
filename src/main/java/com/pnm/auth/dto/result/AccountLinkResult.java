package com.pnm.auth.dto.result;

import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.domain.enums.NextAction;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AccountLinkResult {

    private AuthOutcome outcome;
    private String email;

    private String accessToken;
    private String refreshToken;

    private NextAction nextAction;

    private String message;
}


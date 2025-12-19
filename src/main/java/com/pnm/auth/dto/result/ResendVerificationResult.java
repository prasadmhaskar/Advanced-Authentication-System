package com.pnm.auth.dto.result;

import com.pnm.auth.domain.enums.NextAction;
import com.pnm.auth.domain.enums.ResendVerificationOutcome;
import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ResendVerificationResult {

    private ResendVerificationOutcome outcome;
    private String email;
    private NextAction nextAction; // VERIFY_EMAIL
}


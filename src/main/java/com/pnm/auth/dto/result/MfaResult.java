package com.pnm.auth.dto.result;

import com.pnm.auth.domain.enums.AuthOutcome;
import lombok.*;

@Getter
@Setter
@Builder
public class MfaResult {
    private AuthOutcome outcome;
    private Long tokenId;
}


package com.pnm.auth.dto.result;

import com.pnm.auth.enums.AuthOutcome;
import lombok.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegistrationResult {

    private AuthOutcome outcome;

    private String message;

    private Long verificationTokenId; // optional

    private String email; // useful for frontend
}


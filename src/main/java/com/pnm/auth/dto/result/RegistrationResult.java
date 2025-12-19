package com.pnm.auth.dto.result;

import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.domain.enums.AuthProviderType;
import com.pnm.auth.domain.enums.NextAction;
import jakarta.persistence.Enumerated;
import lombok.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegistrationResult {

    private AuthOutcome outcome;

    private String email; // useful for frontend

    private String linkToken;

    private AuthProviderType existingProvider;
    private AuthProviderType attemptedProvider;

    private NextAction nextAction;
}


package com.pnm.auth.dto.result;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.domain.enums.AuthProviderType;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ResolveOAuthResult {
    private AuthOutcome outcome;

    // success
    private User user;

    // link required
    private String email;
    private AuthProviderType existingProvider;
    private String linkToken;

    @Builder.Default
    private boolean isNewUser = false;
}


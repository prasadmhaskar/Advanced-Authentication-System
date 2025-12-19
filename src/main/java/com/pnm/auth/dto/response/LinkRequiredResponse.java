package com.pnm.auth.dto.response;

import com.pnm.auth.domain.enums.AuthProviderType;
import com.pnm.auth.domain.enums.NextAction;
import lombok.*;

@Getter
@AllArgsConstructor
@Builder
public class LinkRequiredResponse {

    private String email;

    private AuthProviderType existingProvider;

    private AuthProviderType attemptedProvider;

    private NextAction nextAction; // LINK_OAUTH
}


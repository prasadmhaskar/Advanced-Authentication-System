package com.pnm.auth.dto.response;

import com.pnm.auth.domain.enums.AuthProviderType;
import com.pnm.auth.domain.enums.NextAction;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class OAuthLinkRequiredResponse {

    private String email;
    private AuthProviderType provider;
    private String linkToken;     // short-lived
    private NextAction nextAction; // LINK_OAUTH
}

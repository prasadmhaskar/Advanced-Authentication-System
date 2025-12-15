package com.pnm.auth.dto.request;

import com.pnm.auth.domain.enums.AuthProviderType;
import lombok.Data;

@Data
public class LinkOAuthRequest {
    private String providerId;
    private AuthProviderType providerType;
    private String accessToken; // current JWT of logged-in user
}


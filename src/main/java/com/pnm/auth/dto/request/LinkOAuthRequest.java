package com.pnm.auth.dto.request;

import com.pnm.auth.domain.enums.AuthProviderType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class LinkOAuthRequest {

    @NotBlank
    private String linkToken;

    @NotNull
    private AuthProviderType provider;
}




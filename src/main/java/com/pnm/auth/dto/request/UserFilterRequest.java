package com.pnm.auth.dto.request;

import com.pnm.auth.domain.enums.AuthProviderType;
import lombok.Data;

@Data
public class UserFilterRequest {

    private String keyword;               // name/email search
    private AuthProviderType providerType;
    private Boolean emailVerified;
    private String role;
}

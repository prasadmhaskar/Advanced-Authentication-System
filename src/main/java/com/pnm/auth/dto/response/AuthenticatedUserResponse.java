package com.pnm.auth.dto.response;

import lombok.Builder;
import lombok.Data;

import java.util.List;


@Data
@Builder
public class AuthenticatedUserResponse {

    private Long id;
    private String fullName;
    private String email;
    private List<String> roles;
    private boolean emailVerified;
    private boolean mfaEnabled;
}


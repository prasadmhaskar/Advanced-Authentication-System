package com.pnm.auth.dto.response;

import com.pnm.auth.enums.AuthProviderType;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;

@Data
@AllArgsConstructor
public class UserDetailsResponse {

    private String fullName;
    private String email;
    private List<String> roles;
    private AuthProviderType providerType;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}


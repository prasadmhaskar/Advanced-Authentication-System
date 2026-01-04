package com.pnm.auth.dto.request;

import com.pnm.auth.domain.enums.AuthProviderType;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Criteria for filtering users")
public class UserFilterRequest {

    @Schema(description = "Search by partial Email or Full Name", example = "john")
    private String search;

    @Schema(description = "Filter by specific Role", example = "ROLE_USER")
    private String role;

    @Schema(description = "Filter by Active Status", example = "true")
    private Boolean active;

    @Schema(description = "Filter by Auth Provider", example = "GOOGLE")
    private AuthProviderType provider;
}
package com.pnm.auth.dto.result;

import com.pnm.auth.domain.entity.User;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class LinkingResult {
    private User user;
    private AuthenticationResult authTokens;
    private String passwordResetToken; // Null if not needed
}

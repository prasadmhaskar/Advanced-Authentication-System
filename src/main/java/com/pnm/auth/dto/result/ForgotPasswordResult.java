package com.pnm.auth.dto.result;

import com.pnm.auth.enums.AuthOutcome;
import lombok.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ForgotPasswordResult {

    private AuthOutcome outcome;

    private String message;

    private String email;
}


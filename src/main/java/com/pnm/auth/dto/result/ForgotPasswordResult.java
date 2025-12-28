package com.pnm.auth.dto.result;

import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.domain.enums.NextAction;
import lombok.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ForgotPasswordResult {

    private AuthOutcome outcome;

    private String message;

    private String email;

    private NextAction nextAction;

    private Boolean emailSent;
}


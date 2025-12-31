package com.pnm.auth.dto.response;

import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ResendOtpResponse {
    private Boolean emailSent;
    private Long newTokenId;
}

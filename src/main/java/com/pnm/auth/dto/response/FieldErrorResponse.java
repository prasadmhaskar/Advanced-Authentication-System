package com.pnm.auth.dto.response;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class FieldErrorResponse {
    private String field;
    private String message;
}


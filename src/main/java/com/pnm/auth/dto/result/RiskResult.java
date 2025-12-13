package com.pnm.auth.dto.result;

import lombok.*;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class RiskResult {

    private int score;
    private List<String> reasons;

    private boolean blocked;         // score >= 80
    private boolean otpRequired;     // 40 <= score < 80
}


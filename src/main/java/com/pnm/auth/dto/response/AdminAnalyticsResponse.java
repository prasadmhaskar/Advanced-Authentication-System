package com.pnm.auth.dto.response;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AdminAnalyticsResponse {

    private long totalUsers;
    private long activeUsers;
    private long blockedUsers;

    private long mfaEnabledUsers;

    private long suspiciousLoginsToday;
    private long suspiciousLoginsLast7Days;

    private long newUsersToday;
    private long newUsersLast7Days;

    private long highRiskLoginAttempts;
}


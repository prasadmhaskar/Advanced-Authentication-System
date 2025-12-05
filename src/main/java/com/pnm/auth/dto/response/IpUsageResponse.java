package com.pnm.auth.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class IpUsageResponse {
    private String ipAddress;
    private int accountCount;
}

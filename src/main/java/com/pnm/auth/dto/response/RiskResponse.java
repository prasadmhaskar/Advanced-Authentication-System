package com.pnm.auth.dto.response;

import lombok.Builder;
import lombok.Data;

import java.util.Arrays;
import java.util.List;

@Data
@Builder
public class RiskResponse {

    private int riskScore;
    private List<String> reasons;
    private String ip;
    private String country;
    private String city;
    private String device;

    public static RiskResponse from(UserIpLogResponse log) {
        return RiskResponse.builder()
                .riskScore(log.getRiskScore())
                .reasons(log.getRiskReason() != null
                        ? Arrays.asList(log.getRiskReason().split(","))
                        : List.of())
                .ip(log.getIpAddress())
                .country(log.getCountryCode())
                .city(log.getCity())
                .device(log.getDeviceName())
                .build();
    }
}

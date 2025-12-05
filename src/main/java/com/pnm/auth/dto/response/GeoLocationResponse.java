package com.pnm.auth.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GeoLocationResponse {
    private String countryCode; // e.g. "IN", "US"
    private String city;        // e.g. "Mumbai"
}

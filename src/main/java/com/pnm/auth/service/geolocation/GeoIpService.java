package com.pnm.auth.service.geolocation;

import com.pnm.auth.dto.response.GeoLocationResponse;

public interface GeoIpService {
    GeoLocationResponse lookup(String ip);
}

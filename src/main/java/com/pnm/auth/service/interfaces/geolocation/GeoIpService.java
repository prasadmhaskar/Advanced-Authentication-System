package com.pnm.auth.service.interfaces.geolocation;

import com.pnm.auth.dto.response.GeoLocationResponse;

public interface GeoIpService {
    GeoLocationResponse lookup(String ip);
}

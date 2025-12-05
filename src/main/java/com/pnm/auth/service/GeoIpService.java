package com.pnm.auth.service;

import com.pnm.auth.dto.response.GeoLocationResponse;

public interface GeoIpService {
    GeoLocationResponse lookup(String ip);
}

package com.pnm.auth.service.impl.geolocation;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.CityResponse;
import com.pnm.auth.dto.response.GeoLocationResponse;
import com.pnm.auth.integration.geoip.GeoIpDatabase;
import com.pnm.auth.service.geolocation.GeoIpService;
import com.pnm.auth.util.IpUtils;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.InetAddress;

@Service
@RequiredArgsConstructor
@Slf4j
public class GeoIpServiceImpl implements GeoIpService {

    private final GeoIpDatabase geoIpDatabase;

    @Override
    public GeoLocationResponse lookup(String ip) {

        if (ip == null || ip.isBlank()) {
            return null;
        }

        // Skip lookups for internal / private IP addresses
        if (IpUtils.isPrivateIp(ip)) {
            log.debug("GeoIP lookup skipped for private/internal IP={}", ip);
            return null;
        }

        DatabaseReader reader = geoIpDatabase.getReader();

        if (reader == null) {
            log.error("GeoLite2 DB not available; returning null for IP={}", ip);
            return null;
        }

        try {
            InetAddress inetAddress = InetAddress.getByName(ip);

            CityResponse response = reader.city(inetAddress);

            String countryCode = response.getCountry().getIsoCode();
            String city = response.getCity().getName();

            log.debug("GeoIP lookup for IP={} -> country={} city={}", ip, countryCode, city);

            return GeoLocationResponse.builder()
                    .countryCode(countryCode)
                    .city(city)
                    .build();

        } catch (IOException | GeoIp2Exception e) {
            log.warn("GeoIP lookup failed for ip={} reason={}", ip, e.getMessage());
            return null;
        }
    }
}

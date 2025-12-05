package com.pnm.auth.geo;

import com.maxmind.geoip2.DatabaseReader;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;

@Component
@Slf4j
public class GeoIpDatabase {

    private DatabaseReader databaseReader;

    public GeoIpDatabase() {
        try {
            InputStream dbStream = getClass()
                    .getClassLoader()
                    .getResourceAsStream("geoip/GeoLite2-City.mmdb");

            if (dbStream == null) {
                log.error("GeoLite2 database not found in resources/geoip/");
                return;
            }

            this.databaseReader = new DatabaseReader.Builder(dbStream).build();

            log.info("GeoLite2 City database loaded successfully");

        } catch (IOException e) {
            log.error("Failed to load GeoLite2 database: {}", e.getMessage());
        }
    }

    public DatabaseReader getReader() {
        return this.databaseReader;
    }
}

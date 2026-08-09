package com.pnm.auth.util;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class BCryptStandaloneTest {
    public static void main(String[] args) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(10);

        String raw = "Password@123";
        String encoded = encoder.encode(raw);

        long start = System.currentTimeMillis();
        encoder.matches(raw, encoded);
        long end = System.currentTimeMillis();

        System.out.println("Match time: " + (end - start) + " ms");
    }
}

package com.pnm.auth.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.util.SerializationUtils;

import java.io.IOException;
import java.util.Base64;
import java.util.Optional;

public class CookieUtils {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static Optional<Cookie> getCookie(HttpServletRequest request, String name) {
        if (request.getCookies() == null) {
            return Optional.empty();
        }

        for (Cookie cookie : request.getCookies()) {
            if (cookie.getName().equals(name)) {
                return Optional.of(cookie);
            }
        }
        return Optional.empty();
    }

    public static void addCookie(HttpServletResponse response,
                                 String name,
                                 String value,
                                 int maxAge) {

        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(maxAge);
        response.addCookie(cookie);
    }

    public static void deleteCookie(HttpServletRequest request,
                                    HttpServletResponse response,
                                    String name) {

        if (request.getCookies() == null) return;

        for (Cookie cookie : request.getCookies()) {
            if (cookie.getName().equals(name)) {
                cookie.setValue("");
                cookie.setPath("/");
                cookie.setMaxAge(0);
                response.addCookie(cookie);
            }
        }
    }

    public static String serialize(Object object) {
        try {
            return Base64.getUrlEncoder()
                    .encodeToString(objectMapper.writeValueAsBytes(object));
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Cookie serialization failed", e);
        }
    }

    public static <T> T deserialize(Cookie cookie, Class<T> cls) {
        try {
            return objectMapper.readValue(
                    Base64.getUrlDecoder().decode(cookie.getValue()),
                    cls
            );
        } catch (IOException e) {
            return null; // Handle gracefully
        }
    }
}

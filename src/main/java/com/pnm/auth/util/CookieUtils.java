package com.pnm.auth.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.util.SerializationUtils;
import java.util.Base64;
import java.util.Optional;

public class CookieUtils {

    // Inject this or use a static mapper
    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static Optional<Cookie> getCookie(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null && cookies.length > 0) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(name)) {
                    return Optional.of(cookie);
                }
            }
        }
        return Optional.empty();
    }

    public static void addCookie(HttpServletResponse response, String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(maxAge);

        // 🚨 CRITICAL FIX FOR LOCALHOST:
        // If testing on HTTP (not HTTPS), Secure MUST be false.
        // If on HTTPS, it should be true.
        // Ideally, control this via a property, but for debugging assume false or check request.
        cookie.setSecure(false);

        response.addCookie(cookie);
    }

    public static void deleteCookie(HttpServletRequest request, HttpServletResponse response, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null && cookies.length > 0) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(name)) {
                    cookie.setValue("");
                    cookie.setPath("/");
                    cookie.setMaxAge(0);
                    response.addCookie(cookie);
                }
            }
        }
    }

    // ... serialize/deserialize methods using Jackson (as discussed previously) ...
    public static String serialize(Object object) {
        try {
            return Base64.getUrlEncoder()
                    .encodeToString(objectMapper.writeValueAsBytes(object));
        } catch (Exception e) {
            throw new RuntimeException("Cookie serialization failed", e);
        }
    }

    public static <T> T deserialize(Cookie cookie, Class<T> cls) {
        try {
            return objectMapper.readValue(
                    Base64.getUrlDecoder().decode(cookie.getValue()),
                    cls
            );
        } catch (Exception e) {
            return null;
        }
    }
}
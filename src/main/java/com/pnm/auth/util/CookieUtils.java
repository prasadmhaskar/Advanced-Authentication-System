package com.pnm.auth.util;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.util.SerializationUtils;

import java.io.*;
import java.util.Base64;
import java.util.Optional;

public final class CookieUtils {

    private CookieUtils() {
        throw new UnsupportedOperationException("Utility class cannot be instantiated");
    }

    public static Optional<Cookie> getCookie(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
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

        // 🚨 LOCALHOST CONFIGURATION
        // setSecure(false) allows cookies to be sent over HTTP (localhost).
        // In Production (HTTPS), this should be changed to true or handled dynamically.
        cookie.setSecure(false);

        response.addCookie(cookie);
    }

    public static void deleteCookie(HttpServletRequest request, HttpServletResponse response, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
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

    // -----------------------------------------------------------
    // Serialization Methods (Using Java Native Serialization)
    // -----------------------------------------------------------
    // Note: OAuth2AuthorizationRequest is NOT JSON-friendly.
    // We must use standard Java serialization here.


    public static String serialize(Object object) {
        try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
             ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream)) {

            objectOutputStream.writeObject(object);
            return Base64.getUrlEncoder().encodeToString(byteArrayOutputStream.toByteArray());

        } catch (IOException e) {
            throw new IllegalStateException("Failed to serialize object", e);
        }
    }

    public static <T> T deserialize(Cookie cookie, Class<T> cls) {
        if (cookie.getValue() == null || cookie.getValue().isEmpty()) {
            return null;
        }

        byte[] data = Base64.getUrlDecoder().decode(cookie.getValue());

        try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(data);
             ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream)) {

            return cls.cast(objectInputStream.readObject());

        } catch (IOException | ClassNotFoundException e) {
            return null;
        }
    }
}
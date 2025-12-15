package com.pnm.auth.exception.custom;

public class OAuth2LoginFailedException extends RuntimeException {
    public OAuth2LoginFailedException(String message) {
        super(message);
    }
}

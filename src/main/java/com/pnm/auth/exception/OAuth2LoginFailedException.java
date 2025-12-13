package com.pnm.auth.exception;

public class OAuth2LoginFailedException extends RuntimeException {
    public OAuth2LoginFailedException(String message) {
        super(message);
    }
}

package com.pnm.auth.exception.custom;

public class OAuthPasswordLoginNotAllowedException extends RuntimeException {
    public OAuthPasswordLoginNotAllowedException(String message) {
        super(message);
    }
}

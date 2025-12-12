package com.pnm.auth.exception;

public class OAuthLinkFailedException extends RuntimeException {
    public OAuthLinkFailedException(String message) {
        super(message);
    }
}

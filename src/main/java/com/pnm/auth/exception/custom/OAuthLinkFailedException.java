package com.pnm.auth.exception.custom;

public class OAuthLinkFailedException extends RuntimeException {
    public OAuthLinkFailedException(String message) {
        super(message);
    }
}

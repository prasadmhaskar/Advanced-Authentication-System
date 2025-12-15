package com.pnm.auth.exception.custom;

public class TokenGenerationException extends RuntimeException {
    public TokenGenerationException(String message, Exception ex) {
        super(message, ex);
    }

}

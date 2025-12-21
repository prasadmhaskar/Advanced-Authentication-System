package com.pnm.auth.exception.custom;

public class CooldownActiveException extends RuntimeException {
    public CooldownActiveException(String message) {
        super(message);
    }
}

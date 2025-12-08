package com.pnm.auth.exception;

public class HighRiskLoginException extends RuntimeException {
    public HighRiskLoginException(String message) {
        super(message);
    }
}

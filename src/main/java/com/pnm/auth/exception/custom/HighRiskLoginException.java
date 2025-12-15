package com.pnm.auth.exception.custom;

public class HighRiskLoginException extends RuntimeException {
    public HighRiskLoginException(String message) {
        super(message);
    }
}

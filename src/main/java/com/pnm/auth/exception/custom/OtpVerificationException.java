package com.pnm.auth.exception.custom;

public class OtpVerificationException extends RuntimeException {

    public OtpVerificationException(String message) {
        super(message);
    }

    public OtpVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}

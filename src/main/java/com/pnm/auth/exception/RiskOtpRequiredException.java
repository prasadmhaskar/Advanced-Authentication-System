package com.pnm.auth.exception;


public class RiskOtpRequiredException extends RuntimeException {

    private final Long tokenId;

    public RiskOtpRequiredException(String message, Long tokenId) {
        super(message);
        this.tokenId = tokenId;
    }

    public Long getTokenId() {
        return tokenId;
    }
}


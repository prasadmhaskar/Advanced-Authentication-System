package com.pnm.auth.enums;

public enum AuthOutcome {

    SUCCESS,             // Login success

    MFA_REQUIRED,        // User has MFA enabled → OTP required
    RISK_OTP_REQUIRED,   // Medium-risk detected → OTP required

    BLOCKED_HIGH_RISK,   // High risk blocked
    INVALID_CREDENTIALS,
    INVALID_TOKEN,
    EMAIL_NOT_VERIFIED,
    ACCOUNT_BLOCKED,

    REGISTERED,
    PASSWORD_RESET,
    TOKEN_REFRESHED
}


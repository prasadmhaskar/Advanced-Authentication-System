package com.pnm.auth.enums;

public enum AuditAction {

    // -----------------------
    // AUTH + SECURITY ACTIONS
    // -----------------------
    USER_REGISTER,
    LOGIN_ATTEMPT,
    MFA_VERIFY,
    PASSWORD_RESET_REQUEST,
    PASSWORD_RESET,
    CHANGE_PASSWORD,
    LOGOUT,
    OAUTH_LOGIN,
    OAUTH_LINK,
    PROFILE_UPDATE,       // optional

    // -----------------------
    // TRUSTED DEVICE ACTIONS
    // -----------------------
    DEVICE_TRUST_ADD,
    DEVICE_REMOVE,
    DEVICE_REMOVE_OTHERS,

    // -----------------------
    // ADMIN ACTIONS
    // -----------------------
    ADMIN_DELETE_USER,
    ADMIN_BLOCK_USER,
    ADMIN_UNBLOCK_USER,

    // -----------------------
    // REFRESH TOKEN
    // -----------------------
    REFRESH_TOKEN_ROTATION,
    REFRESH_TOKEN_REUSE

    }

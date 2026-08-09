package com.pnm.auth.domain.enums;

public enum AuditAction {

    // security and authentication
    USER_REGISTER,
    LOGIN_ATTEMPT,
    MFA_VERIFY,
    PASSWORD_RESET_REQUEST,
    PASSWORD_RESET,
    CHANGE_PASSWORD,
    LOGOUT,
    OAUTH_LOGIN,
    OAUTH_LINK,
    PROFILE_UPDATE,
    SELF_DELETE,

    // trusted devices
    DEVICE_TRUST_ADD,
    DEVICE_REMOVE,
    DEVICE_REMOVE_OTHERS,

    // admin
    ADMIN_DELETE_USER,
    ADMIN_BLOCK_USER,
    ADMIN_UNBLOCK_USER,

    // refresh token
    REFRESH_TOKEN_ROTATION,
    REFRESH_TOKEN_REUSE,

    // access token
    ACCESS_TOKEN_COMPROMISE

    }

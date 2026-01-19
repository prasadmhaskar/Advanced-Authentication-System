package com.pnm.auth.event;

public record SuccessEvent(
        Long userId,
        String email,
        String ip,
        String userAgent,
        String message)
{}

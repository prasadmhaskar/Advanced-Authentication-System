package com.pnm.auth.event;

public record FailureEvent(
        Long userId,
        String email,
        String ip,
        String userAgent,
        String message
) {}

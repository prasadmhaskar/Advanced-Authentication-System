package com.pnm.auth.event;

public record LoginSuccessEvent(
        Long userId,
        String email,
        String ip,
        String userAgent)
{}

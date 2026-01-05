package com.pnm.auth.web.context;

public record RequestContext(String ip, String userAgent, String path) {}

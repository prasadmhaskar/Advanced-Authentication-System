package com.pnm.auth.service.interfaces.login;

public interface LoginActivityService {

    void recordSuccess(Long userId, String email, String ip, String userAgent);

    void recordFailure(String email, String message, String ip, String userAgent);
}

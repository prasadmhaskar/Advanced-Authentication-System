package com.pnm.auth.service;

public interface LoginActivityService {

    void recordSuccess(Long userId, String email, String ip, String userAgent);

    void recordFailure(String email, String ip, String userAgent, String message);

}

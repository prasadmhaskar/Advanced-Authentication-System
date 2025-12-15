package com.pnm.auth.service.login;

public interface LoginActivityService {

    void recordSuccess(Long userId, String email);

    void recordFailure(String email, String message);
}

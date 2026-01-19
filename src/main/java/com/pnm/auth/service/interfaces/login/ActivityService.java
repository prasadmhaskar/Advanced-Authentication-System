package com.pnm.auth.service.interfaces.login;

public interface ActivityService {

    void recordSuccess(Long userId, String email, String ip, String userAgent, String message);

    void recordFailure(Long userId, String email, String ip, String userAgent, String message);

}

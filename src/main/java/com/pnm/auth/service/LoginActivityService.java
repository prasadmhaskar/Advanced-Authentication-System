package com.pnm.auth.service;

import jakarta.transaction.Transactional;

public interface LoginActivityService {

//    void recordSuccess(Long userId, String email, String ip, String userAgent);
//
//    void recordFailure(String email, String ip, String userAgent, String message);

    // ---------------------------------------------
    // SUCCESS
    // ---------------------------------------------
    @Transactional
    void recordSuccess(Long userId, String email);

    // ---------------------------------------------
    // FAILURE
    // ---------------------------------------------
    @Transactional
    void recordFailure(String email, String message);
}

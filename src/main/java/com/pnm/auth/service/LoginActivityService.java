package com.pnm.auth.service;

import jakarta.transaction.Transactional;

public interface LoginActivityService {

    void recordSuccess(Long userId, String email);

    void recordFailure(String email, String message);
}

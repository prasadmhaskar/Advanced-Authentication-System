package com.pnm.auth.service.auth;

import com.pnm.auth.dto.request.RegisterRequest;
import com.pnm.auth.service.impl.auth.UserPersistenceServiceImpl;

public interface UserPersistenceService {
    UserPersistenceServiceImpl.UserCreationResult saveUserAndCreateToken(RegisterRequest request);
}

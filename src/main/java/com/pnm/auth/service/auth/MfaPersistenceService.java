package com.pnm.auth.service.auth;


import com.pnm.auth.domain.entity.MfaToken;
import com.pnm.auth.domain.entity.User;

public interface MfaPersistenceService {
    MfaToken createMfaToken(User user, boolean riskBased);
    MfaToken rotateMfaToken(Long oldTokenId);
}

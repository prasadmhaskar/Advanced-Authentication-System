package com.pnm.auth.service;

import com.pnm.auth.domain.entity.MfaToken;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.dto.result.MfaResult;
import com.pnm.auth.service.impl.auth.MfaServiceImpl;
import com.pnm.auth.service.interfaces.auth.MfaPersistenceService;
import com.pnm.auth.service.interfaces.email.EmailService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class MfaServiceImplTest {

    @Mock
    private MfaPersistenceService mfaPersistenceService;

    @Mock
    private EmailService emailService;

    @InjectMocks
    private MfaServiceImpl mfaService;

    @Test
    void handleMfaLoginCreatesOtpAndReturnsResult() {
        User user = new User();
        user.setEmail("user@example.com");

        MfaToken token = new MfaToken();
        token.setId(42L);
        token.setOtp("123456");

        when(mfaPersistenceService.createMfaToken(user, false)).thenReturn(token);

        MfaResult result = mfaService.handleMfaLogin(user);

        assertEquals(AuthOutcome.OTP_REQUIRED, result.getOutcome());
        assertEquals(42L, result.getTokenId());
        verify(mfaPersistenceService).createMfaToken(user, false);
        verify(emailService).sendMfaOtpEmail("user@example.com", "123456");
    }

    @Test
    void handleMediumRiskOtpCreatesRiskOtpAndReturnsResult() {
        User user = new User();
        user.setEmail("risk@example.com");

        MfaToken token = new MfaToken();
        token.setId(7L);
        token.setOtp("654321");

        when(mfaPersistenceService.createMfaToken(user, true)).thenReturn(token);

        MfaResult result = mfaService.handleMediumRiskOtp(user);

        assertEquals(AuthOutcome.RISK_OTP_REQUIRED, result.getOutcome());
        assertEquals(7L, result.getTokenId());
        verify(mfaPersistenceService).createMfaToken(user, true);
        verify(emailService).sendMfaOtpEmail("risk@example.com", "654321");
    }
}


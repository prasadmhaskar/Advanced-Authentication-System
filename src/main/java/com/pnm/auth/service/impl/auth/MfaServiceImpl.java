package com.pnm.auth.service.impl.auth;

import com.pnm.auth.dto.result.MfaResult;
import com.pnm.auth.domain.entity.MfaToken;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.service.auth.MfaPersistenceService;
import com.pnm.auth.service.email.EmailService;
import com.pnm.auth.service.auth.MfaService;
import com.pnm.auth.util.MaskingUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
@Slf4j
public class MfaServiceImpl implements MfaService {

    private final MfaPersistenceService mfaPersistenceService;
    private final EmailService emailService;

    // MFA FOR USERS WHO HAVE MFA ENABLED
    @Override
    public MfaResult handleMfaLogin(User user) {

        log.info("MfaService: handling MFA login for email={}", MaskingUtil.maskEmail(user.getEmail()));

        // 1. DB Transaction (Opens and Closes here)
        MfaToken token = mfaPersistenceService.createMfaToken(user, false);

        emailService.sendMfaOtpEmail(user.getEmail(), token.getOtp());

        log.info("MfaService.handleMfaLogin(): OTP generated for email={}", MaskingUtil.maskEmail(user.getEmail()));

        return MfaResult.builder()
                .outcome(AuthOutcome.OTP_REQUIRED)
                .tokenId(token.getId())
                .build();
    }

    // MEDIUM RISK → OTP REQUIRED (RISK-BASED MFA)

    @Override
    public MfaResult handleMediumRiskOtp(User user) {

        log.warn("MfaService: handling RISK OTP for email={}", MaskingUtil.maskEmail(user.getEmail()));

        // 1. DB Transaction
        MfaToken token = mfaPersistenceService.createMfaToken(user, true);

        emailService.sendMfaOtpEmail(user.getEmail(), token.getOtp());

        log.info("MfaService.handleMediumRiskOtp(): Risk OTP generated for email={}", MaskingUtil.maskEmail(user.getEmail()));

        return MfaResult.builder()
                .outcome(AuthOutcome.RISK_OTP_REQUIRED)
                .tokenId(token.getId())
                .build();
    }
}
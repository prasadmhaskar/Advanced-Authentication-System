package com.pnm.auth.orchestrator.auth;

import com.pnm.auth.dto.request.OtpResendRequest;
import com.pnm.auth.domain.entity.MfaToken;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.exception.custom.AccountBlockedException;
import com.pnm.auth.exception.custom.EmailSendFailedException;
import com.pnm.auth.exception.custom.InvalidTokenException;
import com.pnm.auth.repository.MfaTokenRepository;
import com.pnm.auth.service.email.EmailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class ResendOtpOrchestratorImpl implements ResendOtpOrchestrator {

    private final MfaTokenRepository mfaTokenRepository;
    private final EmailService emailService;

    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    @Transactional
    public void resend(OtpResendRequest request) {

        log.info("ResendOtpOrchestrator: resend started tokenId={}", request.getTokenId());

        // 1️⃣ Load existing OTP token
        MfaToken oldToken = mfaTokenRepository.findByIdAndUsedFalse(request.getTokenId())
                .orElseThrow(() -> {
                    log.warn("ResendOtpOrchestrator: token not found id={}", request.getTokenId());
                    return new InvalidTokenException("OTP session expired. Please login again.");
                });

        User user = oldToken.getUser();

        // 2️⃣ Validate user state
        if (!user.isActive()) {
            log.warn("ResendOtpOrchestrator: blocked user attempted resend email={}", user.getEmail());
            throw new AccountBlockedException("Your account has been blocked.");
        }

        try {
            // 3️⃣ Invalidate old OTP
            oldToken.setUsed(true);
            mfaTokenRepository.save(oldToken);

            // 4️⃣ Generate new OTP
            String otp = String.format("%06d", secureRandom.nextInt(1_000_000));

            MfaToken newToken = new MfaToken();
            newToken.setUser(user);
            newToken.setOtp(otp);
            newToken.setRiskBased(oldToken.isRiskBased());
            newToken.setExpiresAt(LocalDateTime.now().plusMinutes(5));
            newToken.setUsed(false);

            mfaTokenRepository.save(newToken);

            // 5️⃣ Send OTP email (resilience + retry handled inside EmailService)
            emailService.sendMfaOtpEmail(user.getEmail(), otp);

            log.info("ResendOtpOrchestrator: OTP resent successfully email={} newTokenId={}",
                    user.getEmail(), newToken.getId());

        } catch (EmailSendFailedException ex) {
            // Already meaningful → propagate
            throw ex;

        } catch (Exception ex) {
            log.error("ResendOtpOrchestrator: resend OTP failed email={} msg={}",
                    user.getEmail(), ex.getMessage(), ex);

            throw new EmailSendFailedException(
                    "Unable to resend OTP. Please try again later."
            );
        }
    }
}
package com.pnm.auth.service.impl.auth;

import com.pnm.auth.dto.result.MfaResult;
import com.pnm.auth.domain.entity.MfaToken;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.exception.custom.EmailSendFailedException;
import com.pnm.auth.repository.MfaTokenRepository;
import com.pnm.auth.service.email.EmailService;
import com.pnm.auth.service.auth.MfaService;
import com.pnm.auth.util.AfterCommitExecutor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class MfaServiceImpl implements MfaService {

    private final MfaTokenRepository mfaTokenRepository;
    private final EmailService emailService;
    private final AfterCommitExecutor afterCommitExecutor;

    private final SecureRandom secureRandom = new SecureRandom();

    // =========================================================
    // MFA FOR USERS WHO HAVE MFA ENABLED
    // =========================================================
    @Override
    @Transactional
    public MfaResult handleMfaLogin(User user) {

        log.info("MfaService: handling MFA login for email={}", user.getEmail());

            mfaTokenRepository.markAllUnusedTokensAsUsed(user.getId());

            String otp = generateOtp();

            MfaToken token = createMfaToken(user, otp, false);
            mfaTokenRepository.save(token);

        CompletableFuture<Boolean> emailResultFuture = new CompletableFuture<>();

        afterCommitExecutor.run(() -> {
            emailService.sendMfaOtpEmail(user.getEmail(), token.getOtp())
                    .thenAccept(emailResultFuture::complete)
                    .exceptionally(ex -> {
                        emailResultFuture.complete(false);
                        return null;
                    });
        });

        boolean emailSent;
        try {
            emailSent = emailResultFuture.get(2, TimeUnit.SECONDS);
        } catch (Exception e) {
            emailSent = false;
        }

            log.info("MfaService.handleMfaLogin(): OTP generated for Mfa login for email={}. Email sent={}", user.getEmail(), emailSent);

            return MfaResult.builder()
                    .outcome(AuthOutcome.OTP_REQUIRED)
                    .tokenId(token.getId())
                    .emailSent(emailSent)
                    .build();

    }

    // =========================================================
    // MEDIUM RISK → OTP REQUIRED (RISK-BASED MFA)
    // =========================================================
    @Override
    @Transactional
    public MfaResult handleMediumRiskOtp(User user) {

        log.warn("MfaService: handling RISK OTP for email={}", user.getEmail());

        try {
            mfaTokenRepository.markAllUnusedTokensAsUsed(user.getId());

            String otp = generateOtp();

            MfaToken token = createMfaToken(user, otp, true);
            mfaTokenRepository.save(token);

            CompletableFuture<Boolean> emailResultFuture = new CompletableFuture<>();

            afterCommitExecutor.run(() -> {
                emailService.sendMfaOtpEmail(user.getEmail(), token.getOtp())
                        .thenAccept(emailResultFuture::complete)
                        .exceptionally(ex -> {
                            emailResultFuture.complete(false);
                            return null;
                        });
            });

            boolean emailSent;
            try {
                emailSent = emailResultFuture.get(2, TimeUnit.SECONDS);
            } catch (Exception e) {
                emailSent = false;
            }

            log.info("MfaService.handleMfaLogin(): OTP generated for medium risk login for email={}. Email sent={}", user.getEmail(), emailSent);


            return MfaResult.builder()
                    .outcome(AuthOutcome.RISK_OTP_REQUIRED)
                    .tokenId(token.getId())
                    .emailSent(emailSent)
                    .build();

        } catch (EmailSendFailedException ex) {
            throw ex; // already meaningful
        }
        catch (Exception ex) {
            log.error("Unexpected error during OTP generation email={}", user.getEmail(), ex);
            throw new EmailSendFailedException("Failed to send OTP. Please try again.");
        }
    }

    private String generateOtp() {
        return String.format("%06d", secureRandom.nextInt(1_000_000));
    }

    private MfaToken createMfaToken(User user, String otp, boolean riskBased) {
        MfaToken token = new MfaToken();
        token.setUser(user);
        token.setOtp(otp);
        token.setRiskBased(riskBased);
        token.setExpiresAt(LocalDateTime.now().plusMinutes(5));
        token.setUsed(false);
        return token;
    }
}

package com.pnm.auth.service.impl.auth;

import com.pnm.auth.dto.result.MfaResult;
import com.pnm.auth.domain.entity.MfaToken;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.service.auth.MfaPersistenceService;
import com.pnm.auth.service.email.EmailService;
import com.pnm.auth.service.auth.MfaService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

//@Service
//@RequiredArgsConstructor
//@Slf4j
//public class MfaServiceImpl implements MfaService {
//
//    private final MfaTokenRepository mfaTokenRepository;
//    private final EmailService emailService;
//    private final AfterCommitExecutor afterCommitExecutor;
//
//    private final SecureRandom secureRandom = new SecureRandom();
//
//    // =========================================================
//    // MFA FOR USERS WHO HAVE MFA ENABLED
//    // =========================================================
//    @Override
//    @Transactional
//    public MfaResult handleMfaLogin(User user) {
//
//        log.info("MfaService: handling MFA login for email={}", user.getEmail());
//
//            mfaTokenRepository.markAllUnusedTokensAsUsed(user.getId());
//
//            String otp = generateOtp();
//
//            MfaToken token = createMfaToken(user, otp, false);
//            mfaTokenRepository.save(token);
//
//        CompletableFuture<Boolean> emailResultFuture = new CompletableFuture<>();
//
//        afterCommitExecutor.run(() -> {
//            emailService.sendMfaOtpEmail(user.getEmail(), token.getOtp())
//                    .thenAccept(emailResultFuture::complete)
//                    .exceptionally(ex -> {
//                        emailResultFuture.complete(false);
//                        return null;
//                    });
//        });
//
//        boolean emailSent;
//        try {
//            emailSent = emailResultFuture.get(2, TimeUnit.SECONDS);
//        } catch (Exception e) {
//            emailSent = false;
//        }
//
//            log.info("MfaService.handleMfaLogin(): OTP generated for Mfa login for email={}. Email sent={}", user.getEmail(), emailSent);
//
//            return MfaResult.builder()
//                    .outcome(AuthOutcome.OTP_REQUIRED)
//                    .tokenId(token.getId())
//                    .emailSent(emailSent)
//                    .build();
//
//    }
//
//    // =========================================================
//    // MEDIUM RISK → OTP REQUIRED (RISK-BASED MFA)
//    // =========================================================
//    @Override
//    @Transactional
//    public MfaResult handleMediumRiskOtp(User user) {
//
//        log.warn("MfaService: handling RISK OTP for email={}", user.getEmail());
//
//        try {
//            mfaTokenRepository.markAllUnusedTokensAsUsed(user.getId());
//
//            String otp = generateOtp();
//
//            MfaToken token = createMfaToken(user, otp, true);
//            mfaTokenRepository.save(token);
//
//            CompletableFuture<Boolean> emailResultFuture = new CompletableFuture<>();
//
//            afterCommitExecutor.run(() -> {
//                emailService.sendMfaOtpEmail(user.getEmail(), token.getOtp())
//                        .thenAccept(emailResultFuture::complete)
//                        .exceptionally(ex -> {
//                            emailResultFuture.complete(false);
//                            return null;
//                        });
//            });
//
//            boolean emailSent;
//            try {
//                emailSent = emailResultFuture.get(2, TimeUnit.SECONDS);
//            } catch (Exception e) {
//                emailSent = false;
//            }
//
//            log.info("MfaService.handleMfaLogin(): OTP generated for medium risk login for email={}. Email sent={}", user.getEmail(), emailSent);
//
//
//            return MfaResult.builder()
//                    .outcome(AuthOutcome.RISK_OTP_REQUIRED)
//                    .tokenId(token.getId())
//                    .emailSent(emailSent)
//                    .build();
//
//        } catch (EmailSendFailedException ex) {
//            throw ex; // already meaningful
//        }
//        catch (Exception ex) {
//            log.error("Unexpected error during OTP generation email={}", user.getEmail(), ex);
//            throw new EmailSendFailedException("Failed to send OTP. Please try again.");
//        }
//    }
//
//    private String generateOtp() {
//        return String.format("%06d", secureRandom.nextInt(1_000_000));
//    }
//
//    private MfaToken createMfaToken(User user, String otp, boolean riskBased) {
//        MfaToken token = new MfaToken();
//        token.setUser(user);
//        token.setOtp(otp);
//        token.setRiskBased(riskBased);
//        token.setExpiresAt(LocalDateTime.now().plusMinutes(5));
//        token.setUsed(false);
//        return token;
//    }
//}


@Service
@RequiredArgsConstructor
@Slf4j
public class MfaServiceImpl implements MfaService {

    private final MfaPersistenceService mfaPersistenceService; // 👈 Inject new service
    private final EmailService emailService;

    // =========================================================
    // MFA FOR USERS WHO HAVE MFA ENABLED
    // =========================================================
    @Override
    public MfaResult handleMfaLogin(User user) {

        log.info("MfaService: handling MFA login for email={}", user.getEmail());

        // 1. DB Transaction (Opens and Closes here)
        MfaToken token = mfaPersistenceService.createMfaToken(user, false);

        // 2. Send Email (Directly, no afterCommit)
        CompletableFuture<Boolean> emailResultFuture = emailService.sendMfaOtpEmail(user.getEmail(), token.getOtp());

        boolean emailSent;
        try {
            emailSent = emailResultFuture.get(1000, TimeUnit.MILLISECONDS);

        } catch (TimeoutException e) {
            log.warn("MfaService.handleMfaLogin(): Email timed out. User will receive it eventually.");
            emailSent = false;

        } catch (ExecutionException e) {
            log.error("MfaService.handleMfaLogin(): CRITICAL EMAIL FAILURE. Cause: {}", e.getCause().getMessage());
            emailSent = false;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            emailSent = false;
        }

        log.info("MfaService.handleMfaLogin(): OTP generated. Email sent={}", emailSent);

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
    // ❌ REMOVE: @Transactional
    public MfaResult handleMediumRiskOtp(User user) {

        log.warn("MfaService: handling RISK OTP for email={}", user.getEmail());

        // 1. DB Transaction
        MfaToken token = mfaPersistenceService.createMfaToken(user, true);

        // 2. Send Email
        CompletableFuture<Boolean> emailResultFuture = emailService.sendMfaOtpEmail(user.getEmail(), token.getOtp());

        boolean emailSent;
        try {
            emailSent = emailResultFuture.get(1000, TimeUnit.MILLISECONDS);

        } catch (TimeoutException e) {
            log.warn("MfaService.handleMediumRiskOtp(): Email timed out. User will receive it eventually.");
            emailSent = false;

        } catch (ExecutionException e) {
            log.error("MfaService.handleMediumRiskOtp(): CRITICAL EMAIL FAILURE. Cause: {}", e.getCause().getMessage());
            emailSent = false;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            emailSent = false;
        }

        log.info("MfaService.handleMediumRiskOtp(): Risk OTP generated. Email sent={}", emailSent);

        return MfaResult.builder()
                .outcome(AuthOutcome.RISK_OTP_REQUIRED)
                .tokenId(token.getId())
                .emailSent(emailSent)
                .build();
    }
}
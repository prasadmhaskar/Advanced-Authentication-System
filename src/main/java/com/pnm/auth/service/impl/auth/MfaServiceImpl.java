package com.pnm.auth.service.impl.auth;

import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.dto.result.MfaResult;
import com.pnm.auth.domain.entity.MfaToken;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.exception.custom.EmailSendFailedException;
import com.pnm.auth.repository.MfaTokenRepository;
import com.pnm.auth.service.email.EmailService;
import com.pnm.auth.service.auth.MfaService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class MfaServiceImpl implements MfaService {

    private final MfaTokenRepository mfaTokenRepository;
    private final EmailService emailService;

    private final SecureRandom secureRandom = new SecureRandom();

    // =========================================================
    // MFA FOR USERS WHO HAVE MFA ENABLED
    // =========================================================
    @Override
    public AuthenticationResult handleMfaLogin(User user) {

        log.info("MfaService: handling MFA login for email={}", user.getEmail());

        try {
            mfaTokenRepository.markAllUnusedTokensAsUsed(user.getId());

            String otp = generateOtp();

            MfaToken token = createMfaToken(user, otp, false);
            mfaTokenRepository.save(token);

            emailService.sendMfaOtpEmail(user.getEmail(), otp);

            return AuthenticationResult.builder()
                    .outcome(AuthOutcome.MFA_REQUIRED)
                    .otpTokenId(token.getId())
                    .message("MFA verification required.")
                    .build();

        } catch (Exception ex) {
            log.error("MfaService: MFA OTP generation failed for user={} msg={}",
                    user.getEmail(), ex.getMessage(), ex);
            throw new EmailSendFailedException("Failed to generate/send MFA OTP. Please try again later.");
        }
    }

    // =========================================================
    // MEDIUM RISK → OTP REQUIRED (RISK-BASED MFA)
    // =========================================================
    @Override
    public MfaResult handleMediumRiskOtp(User user) {

        log.warn("MfaService: handling RISK OTP for email={}", user.getEmail());

        try {
            mfaTokenRepository.markAllUnusedTokensAsUsed(user.getId());

            String otp = generateOtp();

            MfaToken token = createMfaToken(user, otp, true);
            mfaTokenRepository.save(token);

            emailService.sendMfaOtpEmail(user.getEmail(), otp);

            return MfaResult.builder()
                    .outcome(AuthOutcome.RISK_OTP_REQUIRED)
                    .tokenId(token.getId())
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

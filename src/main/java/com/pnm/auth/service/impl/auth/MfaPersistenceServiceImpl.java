package com.pnm.auth.service.impl.auth;

import com.pnm.auth.domain.entity.MfaToken;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.exception.custom.AccountBlockedException;
import com.pnm.auth.exception.custom.InvalidTokenException;
import com.pnm.auth.repository.MfaTokenRepository;
import com.pnm.auth.service.auth.MfaPersistenceService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class MfaPersistenceServiceImpl implements MfaPersistenceService {
    private final MfaTokenRepository mfaTokenRepository;
    private final SecureRandom secureRandom = new SecureRandom();

    @Transactional
    @Override
    public MfaToken createMfaToken(User user, boolean riskBased) {
        // 1. Invalidate old tokens
        mfaTokenRepository.markAllUnusedTokensAsUsed(user.getId());

        // 2. Generate new OTP
        String otp = String.format("%06d", secureRandom.nextInt(1_000_000));

        // 3. Save new token
        MfaToken token = new MfaToken();
        token.setUser(user);
        token.setOtp(otp);
        token.setRiskBased(riskBased);
        token.setExpiresAt(LocalDateTime.now().plusMinutes(5));
        token.setUsed(false);

        return mfaTokenRepository.save(token);
    }

    @Override
    @Transactional
    public MfaToken rotateMfaToken(Long oldTokenId) {
        // 1️⃣ Load existing OTP token
        MfaToken oldToken = mfaTokenRepository.findByIdAndUsedFalse(oldTokenId)
                .orElseThrow(() -> {
                    log.warn("MfaPersistence: token not found or used id={}", oldTokenId);
                    return new InvalidTokenException("OTP session expired. Please login again.");
                });

        User user = oldToken.getUser();

        // 2️⃣ Validate user state
        if (!user.isActive()) {
            log.warn("MfaPersistence: blocked user attempted resend email={}", user.getEmail());
            throw new AccountBlockedException("Your account has been blocked.");
        }

        // 3️⃣ Invalidate old OTP
        oldToken.setUsed(true);
        mfaTokenRepository.save(oldToken);

        // 4️⃣ Generate new OTP
        String otp = String.format("%06d", secureRandom.nextInt(1_000_000));

        MfaToken newToken = new MfaToken();
        newToken.setUser(user);
        newToken.setOtp(otp);
        newToken.setRiskBased(oldToken.isRiskBased()); // Inherit risk status
        newToken.setExpiresAt(LocalDateTime.now().plusMinutes(5));
        newToken.setUsed(false);

        return mfaTokenRepository.save(newToken);
    }
}

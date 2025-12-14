package com.pnm.auth.service.auth;

import com.pnm.auth.dto.result.EmailVerificationResult;
import com.pnm.auth.entity.User;
import com.pnm.auth.entity.VerificationToken;
import com.pnm.auth.enums.AuthOutcome;
import com.pnm.auth.exception.InvalidTokenException;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.repository.VerificationTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class VerifyEmailOrchestratorImpl implements VerifyEmailOrchestrator {

    private final VerificationTokenRepository verificationTokenRepository;
    private final UserRepository userRepository;

    @Override
    @Transactional
    public EmailVerificationResult verify(String token) {

        log.info("VerifyEmailOrchestrator: started tokenPrefix={}", token.substring(0, 8));

        // 1️⃣ Load token
        VerificationToken verificationToken =
                verificationTokenRepository.findByToken(token)
                        .orElseThrow(() -> {
                            log.warn("VerifyEmailOrchestrator: invalid token");
                            return new InvalidTokenException("Invalid or expired token");
                        });

        // 2️⃣ Validate type
        if (!"EMAIL_VERIFICATION".equals(verificationToken.getType())) {
            log.warn("VerifyEmailOrchestrator: token type mismatch expected=EMAIL_VERIFICATION actual={}",
                    verificationToken.getType());
            throw new InvalidTokenException("Invalid verification token");
        }

        // 3️⃣ Validate expiry
        if (verificationToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            log.warn("VerifyEmailOrchestrator: token expired");
            throw new InvalidTokenException("Verification link expired");
        }

        // 4️⃣ Verify user
        User user = verificationToken.getUser();
        user.setEmailVerified(true);
        userRepository.save(user);

        // 5️⃣ Delete token
        verificationTokenRepository.delete(verificationToken);

        log.info("VerifyEmailOrchestrator: email verified email={}", user.getEmail());

        return EmailVerificationResult.builder()
                .outcome(AuthOutcome.SUCCESS)
                .message("Email verified successfully")
                .email(user.getEmail())
                .build();
    }
}


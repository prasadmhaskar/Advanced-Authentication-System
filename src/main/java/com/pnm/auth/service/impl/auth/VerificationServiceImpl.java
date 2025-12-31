package com.pnm.auth.service.impl.auth;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.entity.VerificationToken;
import com.pnm.auth.repository.VerificationTokenRepository;
import com.pnm.auth.service.auth.VerificationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class VerificationServiceImpl implements VerificationService {

    private final VerificationTokenRepository verificationTokenRepository;

    @Value("${verification.token.expiry-minutes}")
    private long verificationExpiryMinutes;

    @Override
    @Transactional
    public String createVerificationToken(User user, String type) {

        log.info("VerificationService.createVerificationToken: Started for email={} type={}",
                user.getEmail(), type);

        // 🔐 Invalidate previous unused tokens of same type
        verificationTokenRepository.invalidateUnusedTokens(user.getId(), type);

        //Creating new object
        VerificationToken verificationToken = new VerificationToken();

        String token = UUID.randomUUID().toString();
        verificationToken.setToken(token);
        verificationToken.setUser(user);
        verificationToken.setType(type);
        verificationToken.setUsedAt(null);
        verificationToken.setExpiresAt(LocalDateTime.now().plusMinutes(verificationExpiryMinutes));
        //Saving to repository
        verificationTokenRepository.save(verificationToken);

        log.info("VerificationService.createVerificationToken: Token created and saved for email={} tokenPrefix={}",
                user.getEmail(), token.substring(0, 8));

        return token;
    }

}

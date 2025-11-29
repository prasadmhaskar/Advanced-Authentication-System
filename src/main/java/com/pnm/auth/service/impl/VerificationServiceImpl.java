package com.pnm.auth.service.impl;

import com.pnm.auth.dto.request.EmailVerificationRequest;
import com.pnm.auth.entity.User;
import com.pnm.auth.entity.VerificationToken;
import com.pnm.auth.exception.InvalidTokenException;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.repository.VerificationTokenRepository;
import com.pnm.auth.service.VerificationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class VerificationServiceImpl implements VerificationService {

    private final VerificationTokenRepository verificationTokenRepository;
    private final UserRepository userRepository;

    @Override
    public String createVerificationToken(User user, String type) {

        log.info("VerificationService.createVerificationToken: Started for email={} type={}",
                user.getEmail(), type);

        //Creating new object
        VerificationToken verificationToken = new VerificationToken();
        //Generating random String as token
        String token = UUID.randomUUID().toString();
        //Setting values for object
        verificationToken.setToken(token);
        LocalDateTime now = LocalDateTime.now();
        verificationToken.setExpiresAt(now.plusMinutes(15));
        verificationToken.setUser(user);
        verificationToken.setType(type);
        //Saving to repository
        verificationTokenRepository.save(verificationToken);
        log.info("VerificationService.createVerificationToken: Token created and saved for email={} tokenPrefix={}",
                user.getEmail(), token.substring(0, 8));
        return token;
    }

    @Override
    public void validateToken(String token, String type) {

        log.info("VerificationService.validateToken: Started tokenPrefix={} type={}",
                token.substring(0, 8), type);
        // 1. Find token in DB
        VerificationToken verificationToken = verificationTokenRepository.findByToken(token).orElseThrow(() -> {
            log.warn("VerificationService.validateToken: Invalid token tokenPrefix={}", token.substring(0, 8));
           throw  new InvalidTokenException("Invalid token");
        });

        // 2. Check type
        if (!verificationToken.getType().equals(type)){
            log.warn("VerificationService.validateToken: Token type mismatch expected={} actual={}", type, verificationToken.getType());
            throw new InvalidTokenException("Token type mismatch");
        }

        // 3. Check expiration
        if (verificationToken.getExpiresAt().isBefore(LocalDateTime.now())){
            log.warn("VerificationService.validateToken: Token expired tokenPrefix={}", token.substring(0, 8));
            throw new InvalidTokenException("Token expired");
        }

        // 4. Mark user as verified
        User user = verificationToken.getUser();
        user.setEmailVerified(true);
        userRepository.save(user);
        log.info("VerificationService.validateToken: User email verified email={}", user.getEmail());

        // 5. Delete token after use (important)
        verificationTokenRepository.delete(verificationToken);
        log.info("VerificationService.validateToken: Token deleted tokenPrefix={}", token.substring(0, 8));

    }
}

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
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class VerificationServiceImpl implements VerificationService {

    private final VerificationTokenRepository verificationTokenRepository;
    private final UserRepository userRepository;

    @Override
    public String createVerificationToken(User user, String type) {
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
        return token;
    }

    @Override
    public void validateToken(String token, String type) {
        // 1. Find token in DB
        VerificationToken verificationToken = verificationTokenRepository.findByToken(token).orElseThrow(() -> new InvalidTokenException("Invalid token"));

        // 2. Check type
        if (!verificationToken.getType().equals(type)){
            throw new InvalidTokenException("Token type mismatch");
        }

        // 3. Check expiration
        if (verificationToken.getExpiresAt().isBefore(LocalDateTime.now())){
            throw new InvalidTokenException("Token expired");
        }

        // 4. Mark user as verified
        User user = verificationToken.getUser();
        user.setEmailVerified(true);
        userRepository.save(user);

        // 5. Delete token after use (important)
        verificationTokenRepository.delete(verificationToken);

    }
}

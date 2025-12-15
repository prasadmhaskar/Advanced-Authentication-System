package com.pnm.auth.service.impl.auth;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.entity.VerificationToken;
import com.pnm.auth.exception.custom.InvalidTokenException;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.repository.VerificationTokenRepository;
import com.pnm.auth.service.auth.VerificationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
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

}

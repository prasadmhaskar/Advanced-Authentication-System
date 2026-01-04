package com.pnm.auth.service.impl.auth;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthProviderType;
import com.pnm.auth.dto.request.RegisterRequest;
import com.pnm.auth.repository.*;
import com.pnm.auth.service.auth.UserPersistenceService;
import com.pnm.auth.service.auth.VerificationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserPersistenceServiceImpl implements UserPersistenceService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final VerificationService verificationService;
    private final LoginActivityRepository loginActivityRepository;
    private final AccountLinkTokenRepository accountLinkTokenRepository;
    private final AuditLogRepository auditLogRepository;
    private final MfaTokenRepository mfaTokenRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final TrustedDeviceRepository trustedDeviceRepository;
    private final UserIpLogRepository userIpLogRepository;
    private final UserOAuthProviderRepository userOAuthProviderRepository;
    private final VerificationTokenRepository verificationTokenRepository;


    public record UserCreationResult(User user, String token) {}

    @Override
    @Transactional // Only the DB work is transactional
    public UserCreationResult saveUserAndCreateToken(RegisterRequest request) {
        String email = request.getEmail().trim().toLowerCase();
        User user = new User();
        user.setFullName(request.getFullName());
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRoles(List.of("ROLE_USER"));
        user.linkProvider(AuthProviderType.EMAIL, email);
        userRepository.save(user);

        // 2. Create Token
        String token = verificationService.createVerificationToken(user, "EMAIL_VERIFICATION");

        // 3. Return BOTH
        return new UserCreationResult(user, token);
    }

    @Override
    @Transactional
    public void deleteUserPermanently(Long userId) {
        log.warn("UserPersistence: Executing HARD DELETE for userId={}", userId);

        loginActivityRepository.deleteByUserId(userId);
        accountLinkTokenRepository.deleteByUserId(userId);
        auditLogRepository.deleteByTargetUserId(userId);
        mfaTokenRepository.deleteByUserId(userId);
        refreshTokenRepository.deleteByUserId(userId);
        trustedDeviceRepository.deleteByUserId(userId);
        userIpLogRepository.deleteByUserId(userId);
        userOAuthProviderRepository.deleteByUserId(userId);
        verificationTokenRepository.deleteByUserId(userId);

        userRepository.deleteById(userId);
    }
}

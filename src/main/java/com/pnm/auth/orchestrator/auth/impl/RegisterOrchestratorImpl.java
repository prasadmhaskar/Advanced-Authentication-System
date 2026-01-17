package com.pnm.auth.orchestrator.auth.impl;

import com.pnm.auth.domain.enums.NextAction;
import com.pnm.auth.dto.request.RegisterRequest;
import com.pnm.auth.dto.result.RegistrationResult;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.orchestrator.auth.RegisterOrchestrator;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.service.interfaces.auth.UserPersistenceService;
import com.pnm.auth.service.interfaces.email.EmailService;
import com.pnm.auth.service.impl.auth.UserPersistenceServiceImpl;
import com.pnm.auth.service.interfaces.ipmonitoring.IpMonitoringService;
import com.pnm.auth.util.MaskingUtil;
import com.pnm.auth.web.context.RequestContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;


@Service
@RequiredArgsConstructor
@Slf4j
public class RegisterOrchestratorImpl implements RegisterOrchestrator {

    private final UserRepository userRepository;
    private final EmailService emailService;
    private final UserPersistenceService userPersistenceService;
    private final IpMonitoringService ipMonitoringService;
    private final PasswordEncoder passwordEncoder;


    @Override
    public RegistrationResult register(RegisterRequest request, RequestContext ctx) {

        String email = request.getEmail().trim().toLowerCase();
        String ip = ctx.ip();
        String ua = ctx.userAgent();

        log.info("RegisterOrchestrator: started for email={}", MaskingUtil.maskEmail(email));

        // Check for restricting multiple accounts registration per device
        //This is just a basic check code for restricting multiple users per device. We have kept limit to 20 because,
        // we have written basic UserAgentParser code. Hence, different clients can have same device signature.
        // In the future, we can replace this with frontEnd fingerprint library which generates unique hash for different users.
        ipMonitoringService.checkRegistrationEligibility(ip, ua);

        // Check if user exists
        Optional<User> optionalUser = userRepository.findByEmail(email);

        if (optionalUser.isPresent()) {
            // SECURITY: Whether the user exists via email or OAuth, we return a fake success.
            // This prevents User Enumeration attacks (hackers checking if an email is registered).
            log.warn("RegisterOrchestrator: Registration attempt for existing email={} (Provider irrelevant). Returning fake success.", MaskingUtil.maskEmail(email));

            // for matching response time with normal registration, we are adding this block for adding time
            passwordEncoder.encode(request.getPassword());

            return RegistrationResult.builder()
                    .outcome(AuthOutcome.REGISTERED)
                    .email(email)
                    .nextAction(NextAction.VERIFY_EMAIL)
                    .build();
        }

        // User does not exist, proceed with Create new user
        UserPersistenceServiceImpl.UserCreationResult result = userPersistenceService.saveUserAndCreateToken(request);

        try {
            ipMonitoringService.recordRegistrationSuccess(result.user().getId(), ip, ua);
        } catch (Exception e) {
            log.error("Failed to log IP for new user={}", MaskingUtil.maskEmail(email), e);
        }

        // Send Verification Email (Async Bridge)
        emailService.sendVerificationEmail(email, result.token());

        log.info("RegisterOrchestrator: finished for email={}", MaskingUtil.maskEmail(email));

        return RegistrationResult.builder()
                .outcome(AuthOutcome.REGISTERED)
                .email(email)
                .nextAction(NextAction.VERIFY_EMAIL)
                .build();
    }
}



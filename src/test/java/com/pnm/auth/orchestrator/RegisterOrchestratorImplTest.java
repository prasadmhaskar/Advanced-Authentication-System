package com.pnm.auth.orchestrator;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthOutcome;
import com.pnm.auth.domain.enums.NextAction;
import com.pnm.auth.dto.request.RegisterRequest;
import com.pnm.auth.dto.result.RegistrationResult;
import com.pnm.auth.event.FailureEvent;
import com.pnm.auth.event.SuccessEvent;
import com.pnm.auth.orchestrator.auth.impl.RegisterOrchestratorImpl;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.service.impl.auth.UserPersistenceServiceImpl;
import com.pnm.auth.service.interfaces.auth.UserPersistenceService;
import com.pnm.auth.service.interfaces.email.EmailService;
import com.pnm.auth.service.interfaces.ipmonitoring.IpMonitoringService;
import com.pnm.auth.web.context.RequestContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RegisterOrchestratorImplTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private EmailService emailService;

    @Mock
    private UserPersistenceService userPersistenceService;

    @Mock
    private IpMonitoringService ipMonitoringService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private ApplicationEventPublisher eventPublisher;

    @InjectMocks
    private RegisterOrchestratorImpl registerOrchestrator;

    @Captor
    private ArgumentCaptor<Object> eventCaptor;

    @Test
    void register_existingUser_returnsFakeSuccess() {
        RegisterRequest request = new RegisterRequest();
        request.setEmail("Existing@Example.com");
        request.setPassword("Password123!");

        RequestContext context = new RequestContext("10.0.0.1", "unit-test-agent", "/register");

        User existingUser = new User();
        existingUser.setEmail("existing@example.com");

        when(userRepository.findByEmail("existing@example.com")).thenReturn(Optional.of(existingUser));

        RegistrationResult result = registerOrchestrator.register(request, context);

        assertThat(result.getOutcome()).isEqualTo(AuthOutcome.REGISTERED);
        assertThat(result.getNextAction()).isEqualTo(NextAction.VERIFY_EMAIL);
        assertThat(result.getEmail()).isEqualTo("existing@example.com");

        verify(ipMonitoringService).checkRegistrationEligibility("10.0.0.1", "unit-test-agent");
        verify(passwordEncoder).encode("Password123!");
        verify(eventPublisher).publishEvent(eventCaptor.capture());
        assertThat(eventCaptor.getValue()).isInstanceOf(FailureEvent.class);
        verify(userPersistenceService, never()).saveUserAndCreateToken(any());
        verify(emailService, never()).sendVerificationEmail(any(), any());
    }

    @Test
    void register_newUser_createsAccountAndSendsEmail() {
        RegisterRequest request = new RegisterRequest();
        request.setEmail("NewUser@Example.com");
        request.setPassword("Password123!");
        request.setFullName("New User");

        RequestContext context = new RequestContext("10.0.0.2", "unit-test-agent", "/register");

        User newUser = new User();
        newUser.setId(55L);
        newUser.setEmail("newuser@example.com");

        UserPersistenceServiceImpl.UserCreationResult creationResult =
                new UserPersistenceServiceImpl.UserCreationResult(newUser, "token-123");

        when(userRepository.findByEmail("newuser@example.com")).thenReturn(Optional.empty());
        when(userPersistenceService.saveUserAndCreateToken(request)).thenReturn(creationResult);

        RegistrationResult result = registerOrchestrator.register(request, context);

        assertThat(result.getOutcome()).isEqualTo(AuthOutcome.REGISTERED);
        assertThat(result.getNextAction()).isEqualTo(NextAction.VERIFY_EMAIL);
        assertThat(result.getEmail()).isEqualTo("newuser@example.com");

        verify(ipMonitoringService).checkRegistrationEligibility("10.0.0.2", "unit-test-agent");
        verify(ipMonitoringService).recordRegistrationIpDetails(55L, "10.0.0.2", "unit-test-agent");
        verify(emailService).sendVerificationEmail("newuser@example.com", "token-123");
        verify(eventPublisher).publishEvent(eventCaptor.capture());
        assertThat(eventCaptor.getValue()).isInstanceOf(SuccessEvent.class);
    }

    @Test
    void register_logsIpFailureButContinuesRegistration() {
        RegisterRequest request = new RegisterRequest();
        request.setEmail("NewUser@Example.com");
        request.setPassword("Password123!");
        request.setFullName("New User");

        RequestContext context = new RequestContext("10.0.0.3", "unit-test-agent", "/register");

        User newUser = new User();
        newUser.setId(88L);
        newUser.setEmail("newuser@example.com");

        UserPersistenceServiceImpl.UserCreationResult creationResult =
                new UserPersistenceServiceImpl.UserCreationResult(newUser, "token-456");

        when(userRepository.findByEmail("newuser@example.com")).thenReturn(Optional.empty());
        when(userPersistenceService.saveUserAndCreateToken(request)).thenReturn(creationResult);
        doThrow(new IllegalStateException("ip log failed"))
                .when(ipMonitoringService)
                .recordRegistrationIpDetails(88L, "10.0.0.3", "unit-test-agent");

        RegistrationResult result = registerOrchestrator.register(request, context);

        assertThat(result.getOutcome()).isEqualTo(AuthOutcome.REGISTERED);
        assertThat(result.getNextAction()).isEqualTo(NextAction.VERIFY_EMAIL);
        assertThat(result.getEmail()).isEqualTo("newuser@example.com");

        verify(ipMonitoringService).checkRegistrationEligibility("10.0.0.3", "unit-test-agent");
        verify(ipMonitoringService).recordRegistrationIpDetails(88L, "10.0.0.3", "unit-test-agent");
        verify(emailService).sendVerificationEmail("newuser@example.com", "token-456");
        verify(eventPublisher).publishEvent(eventCaptor.capture());
        assertThat(eventCaptor.getValue()).isInstanceOf(SuccessEvent.class);
    }
}
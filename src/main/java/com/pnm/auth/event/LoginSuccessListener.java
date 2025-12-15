package com.pnm.auth.event;

import com.pnm.auth.service.login.LoginActivityService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Component
@RequiredArgsConstructor
@Slf4j
public class LoginSuccessListener {

    private final LoginActivityService loginActivityService;

    @Async
    @TransactionalEventListener(
            phase = TransactionPhase.AFTER_COMMIT
    )
    public void handle(LoginSuccessEvent event) {

        log.info("LoginSuccessListener: handling login success userId={}", event.userId());

        loginActivityService.recordSuccess(
                event.userId(),
                event.email()
        );
    }
}


package com.pnm.auth.event;

import com.pnm.auth.service.interfaces.login.ActivityService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Component
@RequiredArgsConstructor
@Slf4j
public class SuccessListener {

    private final ActivityService activityService;

    @Async("activityExecutor")
    @TransactionalEventListener(
            phase = TransactionPhase.AFTER_COMMIT
    )
    public void handle(SuccessEvent event) {

        log.info("SuccessListener: handling login success userId={}", event.userId());

        activityService.recordSuccess(
                event.userId(),
                event.email(),
                event.ip(),
                event.userAgent(),
                event.message()
        );
    }
}


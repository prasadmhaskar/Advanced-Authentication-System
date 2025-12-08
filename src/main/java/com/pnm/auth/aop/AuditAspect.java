package com.pnm.auth.aop;

import com.pnm.auth.service.AuditService;
import com.pnm.auth.util.Audit;
import com.pnm.auth.util.AuthUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Aspect
@Component
@RequiredArgsConstructor
@Slf4j
public class AuditAspect {

    private final AuditService auditService;
    private final AuthUtil authUtil;

    @Around("@annotation(audit)")
    public Object logAudit(ProceedingJoinPoint pjp, Audit audit) throws Throwable {
        Object result;

        Long actorUserId = authUtil.getCurrentUserId();  // You already built this
        HttpServletRequest request =
                ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes())
                        .getRequest();

        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null) ip = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");

        try {
            result = pjp.proceed();
        } catch (Throwable ex) {
            auditService.record(
                    audit.action(),
                    actorUserId,
                    actorUserId,
                    "FAILED: " + audit.description(),
                    ip,
                    userAgent
            );
            throw ex;
        }

        auditService.record(
                audit.action(),
                actorUserId,
                actorUserId,
                audit.description(),
                ip,
                userAgent
        );

        return result;
    }
}


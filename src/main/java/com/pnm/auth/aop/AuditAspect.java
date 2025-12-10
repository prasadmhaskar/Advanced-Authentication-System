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

        Long actorUserId = null;
        try {
            actorUserId = authUtil.getCurrentUserId();
        } catch (Exception ignored) {}

        HttpServletRequest request = null;
        String ip = "UNKNOWN";
        String userAgent = "UNKNOWN";

        ServletRequestAttributes attrs =
                (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();

        if (attrs != null) {
            request = attrs.getRequest();

            if (request != null) {
                ip = request.getHeader("X-Forwarded-For");
                if (ip == null) ip = request.getRemoteAddr();

                userAgent = request.getHeader("User-Agent");
                if (userAgent == null) userAgent = "UNKNOWN";
            }
        }

        try {
            Object result = pjp.proceed();

            // SUCCESS AUDIT
            auditService.record(
                    audit.action(),
                    actorUserId,
                    null,                          // target user not known automatically
                    audit.description(),
                    ip,
                    userAgent
            );

            return result;

        } catch (Throwable ex) {

            // FAILURE AUDIT
            auditService.record(
                    audit.action(),
                    actorUserId,
                    null,
                    "FAILED: " + audit.description(),
                    ip,
                    userAgent
            );

            throw ex;
        }
    }
}


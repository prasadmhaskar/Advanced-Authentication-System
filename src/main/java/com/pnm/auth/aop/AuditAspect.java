package com.pnm.auth.aop;

import com.pnm.auth.service.audit.AuditService;
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
        } catch (Exception ignored) {
            // actor may be null only in rare cases, acceptable
        }

        String ip = "UNKNOWN";
        String userAgent = "UNKNOWN";

        ServletRequestAttributes attrs =
                (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();

        if (attrs != null && attrs.getRequest() != null) {
            HttpServletRequest request = attrs.getRequest();

            ip = request.getHeader("X-Forwarded-For");
            if (ip == null) ip = request.getRemoteAddr();

            userAgent = request.getHeader("User-Agent");
            if (userAgent == null) userAgent = "UNKNOWN";
        }

        Long targetUserId = resolveTargetUserId(pjp, audit, actorUserId);

        try {
            Object result = pjp.proceed();

            auditService.record(
                    audit.action(),
                    actorUserId,
                    targetUserId,
                    audit.description(),
                    ip,
                    userAgent
            );

            return result;

        } catch (Throwable ex) {

            auditService.record(
                    audit.action(),
                    actorUserId,
                    targetUserId,
                    "FAILED: " + audit.description(),
                    ip,
                    userAgent
            );

            throw ex;
        }
    }

    private Long resolveTargetUserId(
            ProceedingJoinPoint pjp,
            Audit audit,
            Long actorUserId
    ) {

        int index = audit.targetUserArgIndex();

        if (index == -1) {
            return actorUserId; // self-action
        }

        Object[] args = pjp.getArgs();

        if (index >= args.length) {
            log.warn("AuditAspect: targetUserArgIndex out of bounds");
            return null;
        }

        Object arg = args[index];

        if (arg instanceof Long userId) {
            return userId;
        }

        log.warn("AuditAspect: targetUserId arg is not Long");
        return null;
    }
}



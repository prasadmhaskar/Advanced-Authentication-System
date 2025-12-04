package com.pnm.auth.aop;

import com.pnm.auth.util.NoLogging;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.*;
import org.aspectj.lang.reflect.MethodSignature;
import org.slf4j.MDC;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.lang.reflect.Method;
import java.util.*;
import java.util.stream.Collectors;

@Aspect
@Component
@Slf4j
@Order(2) // order > request filter order; adjust if needed
public class ServiceLoggingAspect {

    private static final Set<String> SENSITIVE_PARAM_NAMES = Set.of(
            "password", "oldPassword", "newPassword", "otp", "token", "accessToken", "refreshToken"
    );

    @Pointcut("@within(org.springframework.stereotype.Service)")
    public void serviceClassMethods() {}

    @Pointcut("@annotation(com.pnm.auth.util.NoLogging) || @within(com.pnm.auth.util.NoLogging)")
    public void noLogging() {}

    @Around("serviceClassMethods() && !noLogging()")
    public Object aroundService(ProceedingJoinPoint pjp) throws Throwable {
        long start = System.currentTimeMillis();

        MethodSignature sig = (MethodSignature) pjp.getSignature();
        Method method = sig.getMethod();
        String className = sig.getDeclaringTypeName();
        String methodName = method.getName();

        // Build safe args
        String argsStr = buildSafeArgs(sig.getParameterNames(), pjp.getArgs());

        // Read MDC context (requestId etc) set by RequestLoggingFilter
        String requestId = MDC.get("requestId");
        String ip = MDC.get("ip");
        String userAgent = MDC.get("userAgent");
        String path = MDC.get("path");

        log.info("SERVICE_ENTER class={} method={} requestId={} path={} ip={} userAgent={} args={}",
                className, methodName, safe(requestId), safe(path), safe(ip), safe(userAgent), argsStr);

        try {
            Object result = pjp.proceed();

            long elapsed = System.currentTimeMillis() - start;
            String resultSummary = summarizeResult(result);

            log.info("SERVICE_EXIT class={} method={} requestId={} elapsedMs={} result={}",
                    className, methodName, safe(requestId), elapsed, resultSummary);

            return result;
        } catch (Throwable ex) {
            long elapsed = System.currentTimeMillis() - start;
            log.error("SERVICE_EXCEPTION class={} method={} requestId={} elapsedMs={} error={}",
                    className, methodName, safe(requestId), elapsed, ex.toString(), ex);
            throw ex;
        }
    }

    private String buildSafeArgs(String[] paramNames, Object[] args) {
        if (paramNames == null || paramNames.length == 0) return "[]";

        List<String> parts = new ArrayList<>();
        for (int i = 0; i < paramNames.length; i++) {
            String name = paramNames[i];
            Object value = args.length > i ? args[i] : null;

            if (value == null) {
                parts.add(name + "=null");
                continue;
            }

            if (isSensitive(name, value)) {
                parts.add(name + "=<REDACTED>");
            } else {
                parts.add(name + "=" + toShortString(value));
            }
        }
        return "[" + String.join(", ", parts) + "]";
    }

    private boolean isSensitive(String name, Object value) {
        if (SENSITIVE_PARAM_NAMES.contains(name.toLowerCase())) return true;
        if (value instanceof char[] || value instanceof byte[]) return true;
        // guard for DTO containing password fields? best to annotate such DTO methods with @NoLogging if necessary
        return false;
    }

    private String toShortString(Object v) {
        try {
            if (v instanceof Collection) {
                Collection<?> c = (Collection<?>) v;
                return v.getClass().getSimpleName() + "[size=" + c.size() + "]";
            }
            if (v.getClass().isArray()) {
                int length = java.lang.reflect.Array.getLength(v);
                return v.getClass().getComponentType().getSimpleName() + "[] size=" + length;
            }
            String s = v.toString();
            return s.length() > 200 ? s.substring(0, 200) + "...(truncated)" : s;
        } catch (Exception e) {
            return "<unprintable>";
        }
    }

    private String summarizeResult(Object r) {
        if (r == null) return "null";
        if (r instanceof Collection) {
            return r.getClass().getSimpleName() + "[size=" + ((Collection<?>) r).size() + "]";
        }
        String s = r.toString();
        if (s.length() > 500) return s.substring(0, 500) + "...(truncated)";
        return s;
    }

    private String safe(String s) {
        return s == null ? "-" : s;
    }
}

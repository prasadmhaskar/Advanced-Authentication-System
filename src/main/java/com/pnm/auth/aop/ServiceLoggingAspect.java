package com.pnm.auth.aop;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.*;
import org.aspectj.lang.reflect.MethodSignature;
import org.slf4j.MDC;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import java.lang.reflect.Method;
import java.util.*;

@Aspect
@Component
@Slf4j
@Order(2)
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

        // Read MDC values set by RequestLoggingFilter
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

    // guard for DTO containing password fields
    private boolean isSensitive(String name, Object value) {
        if (SENSITIVE_PARAM_NAMES.contains(name.toLowerCase())) return true;
        return value instanceof char[] || value instanceof byte[];
    }

    private String toShortString(Object v) {
        try {
            if (v instanceof Collection<?> c) {
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

        Class<?> clazz = r.getClass();

        // Check for sensitive DTOs by package or annotation
        if (clazz.getPackage().getName().contains("dto") ||
                clazz.getSimpleName().endsWith("DTO") ||
                clazz.getSimpleName().endsWith("Response")) {
            return clazz.getSimpleName() + " <REDACTED>";
        }

        if (r instanceof Collection<?> c) {
            return clazz.getSimpleName() + "[size=" + c.size() + "]";
        }

        if (clazz.isArray()) {
            int length = java.lang.reflect.Array.getLength(r);
            return clazz.getComponentType().getSimpleName() + "[] size=" + length;
        }

        // For primitive/wrapper types and simple classes, show the value
        String className = clazz.getSimpleName();
        if (className.equals("String") || className.equals("Integer") ||
                className.equals("Long") || className.equals("Boolean")) {
            String s = r.toString();
            return s.length() > 100 ? s.substring(0, 100) + "...(truncated)" : s;
        }

        // For other classes, just return class name
        return clazz.getSimpleName();
    }

    private String safe(String s) {
        return s == null ? "-" : s;
    }
}

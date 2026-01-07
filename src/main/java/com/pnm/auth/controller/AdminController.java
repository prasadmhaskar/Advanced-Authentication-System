package com.pnm.auth.controller;

import com.pnm.auth.dto.request.LoginActivityFilterRequest;
import com.pnm.auth.dto.request.UserFilterRequest;
import com.pnm.auth.dto.response.*;
import com.pnm.auth.service.admin.AdminAnalyticsService;
import com.pnm.auth.service.admin.AdminService;
import com.pnm.auth.service.audit.AuditService;
import com.pnm.auth.service.impl.admin.AdminServiceImpl;
import com.pnm.auth.service.ipmonitoring.IpMonitoringService;
import com.pnm.auth.web.context.RequestContext;
import com.pnm.auth.web.filter.RequestContextFilter;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springdoc.core.annotations.ParameterObject;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
@Tag(name = "Admin Management", description = "Endpoints for user management and analytics")
@PreAuthorize("hasRole('ADMIN')")
@Slf4j
public class AdminController {

    private final AdminService adminService;
    private final IpMonitoringService ipMonitoringService;
    private final AuditService auditService;
    private final AdminAnalyticsService adminAnalyticsService;

    @GetMapping("/users")
    @Operation(summary = "Get Users List", description = "Fetch users with pagination, sorting, and filtering.")
    public ResponseEntity<ApiResponse<PagedResponse<UserAdminResponse>>> getAllUsers(
            @ParameterObject UserFilterRequest filter,
            @ParameterObject Pageable pageable,
            HttpServletRequest httpServletRequest
    ) {
        RequestContext ctx = (RequestContext) httpServletRequest.getAttribute(RequestContextFilter.REQUEST_CONTEXT_ATTR);

        log.info("AdminController.getAllUsers(): started ip={}",ctx.ip());

        PagedResponse<UserAdminResponse> users = adminService.getAllUsers(filter, pageable);

        log.info("AdminController.getAllUsers(): finished ip={}",ctx.ip());

        return ResponseEntity.ok(ApiResponse.success(
                "USERS_FETCHED",
                "Users fetched successfully",
                users,
                ctx.path()
        ));
    }


    @DeleteMapping("/users/{id}")
    public ResponseEntity<ApiResponse<Void>> deleteUser(@PathVariable Long id, HttpServletRequest httpServletRequest) {

        RequestContext ctx = (RequestContext) httpServletRequest.getAttribute(RequestContextFilter.REQUEST_CONTEXT_ATTR);

        log.info("AdminController.deleteUser(): started ip={} for id={}",ctx.ip(), id);

        adminService.deleteUser(id);

        log.info("AdminController.deleteUser(): finished ip={} for id={}",ctx.ip(), id);

        ApiResponse<Void> body = ApiResponse.success(
                "USER_DELETED",
                "User deleted successfully",
                null,
                ctx.path()
        );
        return ResponseEntity.ok(body);
    }

    @PatchMapping("/users/{id}/block")
    public ResponseEntity<ApiResponse<AdminServiceImpl.BlockUserResult>> blockUser(@PathVariable Long id, HttpServletRequest httpServletRequest) {

        RequestContext ctx = (RequestContext) httpServletRequest.getAttribute(RequestContextFilter.REQUEST_CONTEXT_ATTR);

        log.info("AdminController.blockUser(): started ip={} for id={}",ctx.ip(), id);

        AdminServiceImpl.BlockUserResult result = adminService.blockUser(id);

        log.info("AdminController.blockUser(): finished ip={} for id={}",ctx.ip(), id);

        ApiResponse<AdminServiceImpl.BlockUserResult> body = ApiResponse.success(
                result.code(),
                result.message(),
                null,
                ctx.path()
        );
        return ResponseEntity.ok(body);
    }

    @PatchMapping("/users/{id}/unblock")
    public ResponseEntity<ApiResponse<AdminServiceImpl.UnblockUserResult>> unblockUser(@PathVariable Long id, HttpServletRequest httpServletRequest) {

        RequestContext ctx = (RequestContext) httpServletRequest.getAttribute(RequestContextFilter.REQUEST_CONTEXT_ATTR);

        log.info("AdminController.unblockUser(): started ip={} for id={}",ctx.ip(), id);

        AdminServiceImpl.UnblockUserResult result = adminService.unblockUser(id);

        log.info("AdminController.unblockUser(): finished ip={} for id={}",ctx.ip(), id);

        ApiResponse<AdminServiceImpl.UnblockUserResult> body = ApiResponse.success(
                result.code(),
                result.message(),
                null,
                ctx.path()
        );
        return ResponseEntity.ok(body);
    }

    @GetMapping("/users/login-activity")
    @Operation(summary = "Get Login Activities", description = "Fetch login logs with filtering and pagination")
    public ResponseEntity<ApiResponse<PagedResponse<LoginActivityResponse>>> getLoginActivities(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @ParameterObject LoginActivityFilterRequest filter,
            HttpServletRequest httpServletRequest
    ) {
        RequestContext ctx = (RequestContext) httpServletRequest.getAttribute(RequestContextFilter.REQUEST_CONTEXT_ATTR);

        log.info("AdminController.getLoginActivities(): started ip={} page={} size={}", ctx.ip(), page, size);

        PagedResponse<LoginActivityResponse> response = adminService.getLoginActivities(page, size, filter);

        log.info("AdminController.getLoginActivities(): finished ip={} page={} size={}", ctx.ip(), page, size);

        return ResponseEntity.ok(ApiResponse.success(
                "LOGIN_ACTIVITIES_FETCHED",
                "Login activities fetched successfully",
                response,
                ctx.path()
        ));
    }

    @GetMapping("/users/login-activity/{id}")
    @Operation(summary = "Get Login Activity By ID", description = "Fetch a single login activity detail")
    public ResponseEntity<ApiResponse<LoginActivityResponse>> getActivityById(
            @PathVariable Long id,
            HttpServletRequest httpServletRequest
    ) {
        RequestContext ctx = (RequestContext) httpServletRequest.getAttribute(RequestContextFilter.REQUEST_CONTEXT_ATTR);

        log.info("AdminController.getActivityById(): started ip={} for id={}",ctx.ip(), id);

        LoginActivityResponse activityById = adminService.getActivityById(id);

        log.info("AdminController.getActivityById(): finished ip={} for id={}",ctx.ip(), id);

        return ResponseEntity.ok(ApiResponse.success(
                "LOGIN_ACTIVITY_FETCHED",
                "Login activity fetched for id=" + id,
                activityById,
                ctx.path()
        ));
    }


    @GetMapping("/security/ip/user/{userId}/recent")
    public ResponseEntity<ApiResponse<List<UserIpLogResponse>>> getRecentIpsForUser(
            @PathVariable Long userId, HttpServletRequest httpServletRequest
    ) {
        RequestContext ctx = (RequestContext) httpServletRequest.getAttribute(RequestContextFilter.REQUEST_CONTEXT_ATTR);

        log.info("AdminController.getRecentIpsForUser(): started ip={} for id={}",ctx.ip(), userId);

        List<UserIpLogResponse> recentIps = ipMonitoringService.getRecentIpsForUser(userId);

        ApiResponse<List<UserIpLogResponse>> body = ApiResponse.success(
                "RECENT_IPS_FETCHED",
                "Recent IPs fetched for userId " + userId,
                recentIps,
                ctx.path()
        );
        return ResponseEntity.ok(body);
    }


    @GetMapping("/security/ip/usage")
    public ResponseEntity<ApiResponse<IpUsageResponse>> getIpUsage(
            @RequestParam String ip, HttpServletRequest httpServletRequest
    ) {
        RequestContext ctx = (RequestContext) httpServletRequest.getAttribute(RequestContextFilter.REQUEST_CONTEXT_ATTR);

        log.info("AdminController.getIpUsage(): started ip={} for ip={}",ctx.ip(), ip);

        IpUsageResponse response = ipMonitoringService.countIpUsage(ip);

        log.info("AdminController.getIpUsage(): finished ip={} for ip={}",ctx.ip(), ip);

        ApiResponse<IpUsageResponse> body = ApiResponse.success(
                "IP_USAGE_FETCHED",
                "IP usage fetched for ip " + ip,
                response,
                ctx.path()
        );
        return ResponseEntity.ok(body);
    }


    @GetMapping("/security/ip/log/{id}")
    public ResponseEntity<ApiResponse<UserIpLogResponse>> getSingleIpLog(
            @PathVariable Long id, HttpServletRequest httpServletRequest
    ) {
        RequestContext ctx = (RequestContext) httpServletRequest.getAttribute(RequestContextFilter.REQUEST_CONTEXT_ATTR);

        log.info("AdminController.getSingleIpLog(): started ip={} for id={}",ctx.ip(), id);

        UserIpLogResponse logEntry = ipMonitoringService.getById(id);

        log.info("AdminController.getSingleIpLog(): finished ip={} for id={}",ctx.ip(), id);

        ApiResponse<UserIpLogResponse> body = ApiResponse.success(
                "IP_LOG_ENTRY_FETCHED",
                "IP log entry fetched for id " + id,
                logEntry,
                ctx.path()
        );
        return ResponseEntity.ok(body);
    }

    @GetMapping
    public ResponseEntity<ApiResponse<PagedResponse<AuditLogResponse>>> getAuditLogs(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            HttpServletRequest httpServletRequest
    ) {
        RequestContext ctx = (RequestContext) httpServletRequest.getAttribute(RequestContextFilter.REQUEST_CONTEXT_ATTR);

        log.info("AuditController.getAuditLogs(): started ip={} page={} size={}", ctx.ip(), page, size);

        PagedResponse<AuditLogResponse> response = auditService.getAll(page, size);

        log.info("AuditController.getAuditLogs(): finished ip={} page={} size={}", ctx.ip(), page, size);

        ApiResponse<PagedResponse<AuditLogResponse>> body = ApiResponse.success(
                "AUDIT_LOGS_FETCHED",
                "Audit logs fetched successfully",
                response,
                ctx.path()
        );

        return ResponseEntity.ok(body);
    }

    @GetMapping("/analytics")
    public ResponseEntity<ApiResponse<AdminAnalyticsResponse>> getAnalytics(HttpServletRequest httpServletRequest) {

        RequestContext ctx = (RequestContext) httpServletRequest.getAttribute(RequestContextFilter.REQUEST_CONTEXT_ATTR);

        log.info("AdminController.getAnalytics(): started ip={}", ctx.ip());

        AdminAnalyticsResponse analytics = adminAnalyticsService.getAnalytics();

        log.info("AdminController.getAnalytics(): finished ip={}", ctx.ip());

        ApiResponse<AdminAnalyticsResponse> body = ApiResponse.success(
                "ADMIN_ANALYTICS_FETCHED",
                "Admin analytics fetched successfully",
                analytics,
                ctx.path()
        );
        return ResponseEntity.ok(body);
    }
}

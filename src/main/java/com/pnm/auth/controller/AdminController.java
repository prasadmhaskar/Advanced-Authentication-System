package com.pnm.auth.controller;

import com.pnm.auth.dto.request.CreateAdminRequest;
import com.pnm.auth.dto.request.LoginActivityFilterRequest;
import com.pnm.auth.dto.request.UserFilterRequest;
import com.pnm.auth.dto.response.*;
import com.pnm.auth.service.admin.AdminAnalyticsService;
import com.pnm.auth.service.admin.AdminService;
import com.pnm.auth.service.audit.AuditService;
import com.pnm.auth.service.impl.admin.AdminServiceImpl;
import com.pnm.auth.service.ipmonitoring.IpMonitoringService;
import com.pnm.auth.util.MaskingUtil;
import com.pnm.auth.web.context.RequestContext;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
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
            RequestContext ctx
    ) {

        log.info("AdminController.getAllUsers(): started");

        PagedResponse<UserAdminResponse> users = adminService.getAllUsers(filter, pageable);

        log.info("AdminController.getAllUsers(): finished");

        return ResponseEntity.ok(ApiResponse.success(
                "USERS_FETCHED",
                "Users fetched successfully",
                users,
                ctx.path()
        ));
    }


    @DeleteMapping("/users/{id}")
    public ResponseEntity<ApiResponse<Void>> deleteUser(@PathVariable Long id, RequestContext ctx) {

        log.info("AdminController.deleteUser(): started for id={}", id);

        adminService.deleteUser(id);

        log.info("AdminController.deleteUser(): finished for id={}", id);

        ApiResponse<Void> body = ApiResponse.success(
                "USER_DELETED",
                "User deleted successfully",
                null,
                ctx.path()
        );
        return ResponseEntity.ok(body);
    }

    @PatchMapping("/users/{id}/block")
    public ResponseEntity<ApiResponse<AdminServiceImpl.BlockUserResult>> blockUser(@PathVariable Long id,
                                                                                   RequestContext ctx) {

        log.info("AdminController.blockUser(): started for id={}", id);

        AdminServiceImpl.BlockUserResult result = adminService.blockUser(id);

        log.info("AdminController.blockUser(): finished for id={}", id);

        ApiResponse<AdminServiceImpl.BlockUserResult> body = ApiResponse.success(
                result.code(),
                result.message(),
                null,
                ctx.path()
        );
        return ResponseEntity.ok(body);
    }

    @PatchMapping("/users/{id}/unblock")
    public ResponseEntity<ApiResponse<AdminServiceImpl.UnblockUserResult>> unblockUser(@PathVariable Long id,
                                                                                       RequestContext ctx) {

        log.info("AdminController.unblockUser(): started for id={}", id);

        AdminServiceImpl.UnblockUserResult result = adminService.unblockUser(id);

        log.info("AdminController.unblockUser(): finished for id={}", id);

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
            RequestContext ctx
    ) {

        log.info("AdminController.getLoginActivities(): started for page={} size={}", page, size);

        PagedResponse<LoginActivityResponse> response = adminService.getLoginActivities(page, size, filter);

        log.info("AdminController.getLoginActivities(): finished for page={} size={}", page, size);

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
            RequestContext ctx
    ) {
        log.info("AdminController.getActivityById(): started for id={}", id);

        LoginActivityResponse activityById = adminService.getActivityById(id);

        log.info("AdminController.getActivityById(): finished for id={}", id);

        return ResponseEntity.ok(ApiResponse.success(
                "LOGIN_ACTIVITY_FETCHED",
                "Login activity fetched for id=" + id,
                activityById,
                ctx.path()
        ));
    }


    @GetMapping("/security/ip/user/{userId}/recent")
    public ResponseEntity<ApiResponse<List<UserIpLogResponse>>> getRecentIpsForUser(
            @PathVariable Long userId, RequestContext ctx
    ) {

        log.info("AdminController.getRecentIpsForUser(): started for id={}", userId);

        List<UserIpLogResponse> recentIps = ipMonitoringService.getRecentIpsForUser(userId);

        log.info("AdminController.getRecentIpsForUser(): finished for id={}", userId);

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
            @RequestParam String ip, RequestContext ctx
    ) {

        log.info("AdminController.getIpUsage(): started for ip={}", ip);

        IpUsageResponse response = ipMonitoringService.countIpUsage(ip);

        log.info("AdminController.getIpUsage(): finished for ip={}", ip);

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
            @PathVariable Long id, RequestContext ctx
    ) {

        log.info("AdminController.getSingleIpLog(): started for id={}", id);

        UserIpLogResponse logEntry = ipMonitoringService.getById(id);

        log.info("AdminController.getSingleIpLog(): finished for id={}", id);

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
            RequestContext ctx
    ) {

        log.info("AuditController.getAuditLogs(): started for page={} size={}", page, size);

        PagedResponse<AuditLogResponse> response = auditService.getAll(page, size);

        log.info("AuditController.getAuditLogs(): finished for page={} size={}", page, size);

        ApiResponse<PagedResponse<AuditLogResponse>> body = ApiResponse.success(
                "AUDIT_LOGS_FETCHED",
                "Audit logs fetched successfully",
                response,
                ctx.path()
        );

        return ResponseEntity.ok(body);
    }

    @GetMapping("/analytics")
    public ResponseEntity<ApiResponse<AdminAnalyticsResponse>> getAnalytics(RequestContext ctx) {

        log.info("AdminController.getAnalytics(): started");

        AdminAnalyticsResponse analytics = adminAnalyticsService.getAnalytics();

        log.info("AdminController.getAnalytics(): finished");

        ApiResponse<AdminAnalyticsResponse> body = ApiResponse.success(
                "ADMIN_ANALYTICS_FETCHED",
                "Admin analytics fetched successfully",
                analytics,
                ctx.path()
        );
        return ResponseEntity.ok(body);
    }

    @PutMapping("/create-admin")
    @Operation(summary = "Create Admin", description = "Appoint normal user to admin")
    public ResponseEntity<ApiResponse<AdminServiceImpl.CreateAdminResult>> createAdmin(RequestContext ctx, @RequestBody @Valid CreateAdminRequest request){

        log.info("AdminController.createAdmin(): started for email={}", MaskingUtil.maskEmail(request.getEmail()));

        AdminServiceImpl.CreateAdminResult adminResult = adminService.createAdmin(request.getEmail());

        log.info("AdminController.createAdmin(): finished for email={}", MaskingUtil.maskEmail(request.getEmail()));

        return ResponseEntity.ok(
                ApiResponse.success(
                        adminResult.code(),
                        adminResult.message(),
                        null,
                        ctx.path()));
    }
}

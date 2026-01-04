package com.pnm.auth.controller;

import com.pnm.auth.dto.request.LoginActivityFilterRequest;
import com.pnm.auth.dto.request.UserFilterRequest;
import com.pnm.auth.dto.response.*;
import com.pnm.auth.service.admin.AdminAnalyticsService;
import com.pnm.auth.service.admin.AdminService;
import com.pnm.auth.service.audit.AuditService;
import com.pnm.auth.service.auth.UserPersistenceService;
import com.pnm.auth.service.impl.admin.AdminServiceImpl;
import com.pnm.auth.service.ipmonitoring.IpMonitoringService;
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
    private final UserPersistenceService userPersistenceService;

    @GetMapping("/users")
    @Operation(summary = "Get Users List", description = "Fetch users with pagination, sorting, and filtering.")
    public ResponseEntity<ApiResponse<PagedResponse<UserAdminResponse>>> getAllUsers(
            // @ParameterObject flattens the UserFilterRequest into query params (search, role, etc.)
            @ParameterObject UserFilterRequest filter,
            @ParameterObject Pageable pageable
    ) {
        PagedResponse<UserAdminResponse> users = adminService.getAllUsers(filter, pageable);

        return ResponseEntity.ok(ApiResponse.success(
                "USERS_FETCHED",
                "Users fetched successfully",
                users,
                "/api/admin/users"
        ));
    }


    @DeleteMapping("/users/{id}")
    public ResponseEntity<ApiResponse<Void>> deleteUser(
            @PathVariable Long id,
            HttpServletRequest request) {

        log.info("AdminController.deleteUser(): Started for id={}", id);
        adminService.deleteUser(id);
        log.info("AdminController.deleteUser(): Finished for id={}", id);

        ApiResponse<Void> body = ApiResponse.success(
                "USER_DELETED",
                "User deleted successfully",
                null,
                request.getRequestURI()
        );
        return ResponseEntity.ok(body);
    }

    @PatchMapping("/users/{id}/block")
    public ResponseEntity<ApiResponse<AdminServiceImpl.BlockUserResult>> blockUser(@PathVariable Long id, HttpServletRequest request) {

        log.info("AdminController.blockUser(): started for id={}", id);

        AdminServiceImpl.BlockUserResult result = adminService.blockUser(id);

        log.info("AdminController.blockUser(): finished for id={}", id);
        ApiResponse<AdminServiceImpl.BlockUserResult> body = ApiResponse.success(
                result.code(),
                result.message(),
                null,
                request.getRequestURI()
        );
        return ResponseEntity.ok(body);
    }

    @PatchMapping("/users/{id}/unblock")
    public ResponseEntity<ApiResponse<AdminServiceImpl.UnblockUserResult>> unblockUser(@PathVariable Long id, HttpServletRequest request) {

        log.info("AdminController.unblockUser(): started for id={}", id);

        AdminServiceImpl.UnblockUserResult result = adminService.unblockUser(id);

        log.info("AdminController.unblockUser(): finished for id={}", id);
        ApiResponse<AdminServiceImpl.UnblockUserResult> body = ApiResponse.success(
                result.code(),
                result.message(),
                null,
                request.getRequestURI()
        );
        return ResponseEntity.ok(body);
    }

    @GetMapping("/users/login-activity")
    @Operation(summary = "Get Login Activities", description = "Fetch login logs with filtering and pagination")
    public ResponseEntity<ApiResponse<PagedResponse<LoginActivityResponse>>> getLoginActivities(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @ParameterObject LoginActivityFilterRequest filter,
            HttpServletRequest request
    ) {
        PagedResponse<LoginActivityResponse> response = adminService.getLoginActivities(page, size, filter);

        return ResponseEntity.ok(ApiResponse.success(
                "LOGIN_ACTIVITIES_FETCHED",
                "Login activities fetched successfully",
                response,
                request.getRequestURI()
        ));
    }

    @GetMapping("/users/login-activity/{id}")
    @Operation(summary = "Get Login Activity By ID", description = "Fetch a single login activity detail")
    public ResponseEntity<ApiResponse<LoginActivityResponse>> getActivityById(
            @PathVariable Long id,
            HttpServletRequest request
    ) {
        LoginActivityResponse activityById = adminService.getActivityById(id);

        return ResponseEntity.ok(ApiResponse.success(
                "LOGIN_ACTIVITY_FETCHED",
                "Login activity fetched for id=" + id,
                activityById,
                request.getRequestURI()
        ));
    }


    @GetMapping("/security/ip/user/{userId}/recent")
    public ResponseEntity<ApiResponse<List<UserIpLogResponse>>> getRecentIpsForUser(
            @PathVariable Long userId, HttpServletRequest request
    ) {
        List<UserIpLogResponse> recentIps = ipMonitoringService.getRecentIpsForUser(userId);

        ApiResponse<List<UserIpLogResponse>> body = ApiResponse.success(
                "RECENT_IPS_FETCHED",
                "Recent IPs fetched for userId " + userId,
                recentIps,
                request.getRequestURI()
        );
        return ResponseEntity.ok(body);
    }


    @GetMapping("/security/ip/usage")
    public ResponseEntity<ApiResponse<IpUsageResponse>> getIpUsage(
            @RequestParam String ip, HttpServletRequest request
    ) {
        IpUsageResponse response = ipMonitoringService.countIpUsage(ip);

        ApiResponse<IpUsageResponse> body = ApiResponse.success(
                "IP_USAGE_FETCHED",
                "IP usage fetched for ip " + ip,
                response,
                request.getRequestURI()
        );
        return ResponseEntity.ok(body);
    }


    @GetMapping("/security/ip/log/{id}")
    public ResponseEntity<ApiResponse<UserIpLogResponse>> getSingleIpLog(
            @PathVariable Long id, HttpServletRequest request
    ) {
        UserIpLogResponse logEntry = ipMonitoringService.getById(id);

        ApiResponse<UserIpLogResponse> body = ApiResponse.success(
                "IP_LOG_ENTRY_FETCHED",
                "IP log entry fetched for id " + id,
                logEntry,
                request.getRequestURI()
        );
        return ResponseEntity.ok(body);
    }

    @GetMapping
    public ResponseEntity<ApiResponse<PagedResponse<AuditLogResponse>>> getAuditLogs(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            HttpServletRequest request
    ) {

        log.info("AuditController.getAuditLogs(): Started page={} size={}", page, size);

        PagedResponse<AuditLogResponse> response = auditService.getAll(page, size);

        ApiResponse<PagedResponse<AuditLogResponse>> body = ApiResponse.success(
                "AUDIT_LOGS_FETCHED",
                "Audit logs fetched successfully",
                response,
                request.getRequestURI()
        );

        return ResponseEntity.ok(body);
    }

    @GetMapping("/analytics")
    public ResponseEntity<ApiResponse<AdminAnalyticsResponse>> getAnalytics(HttpServletRequest request) {

        log.info("AdminController.getAnalytics(): started");

        AdminAnalyticsResponse analytics = adminAnalyticsService.getAnalytics();

        ApiResponse<AdminAnalyticsResponse> body = ApiResponse.success(
                "ADMIN_ANALYTICS_FETCHED",
                "Admin analytics fetched successfully",
                analytics,
                request.getRequestURI()
        );
        return ResponseEntity.ok(body);
    }
}

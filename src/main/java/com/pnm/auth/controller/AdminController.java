package com.pnm.auth.controller;

import com.pnm.auth.dto.request.LoginActivityFilterRequest;
import com.pnm.auth.dto.request.UserFilterRequest;
import com.pnm.auth.dto.response.*;
import com.pnm.auth.service.admin.AdminAnalyticsService;
import com.pnm.auth.service.admin.AdminService;
import com.pnm.auth.service.audit.AuditService;
import com.pnm.auth.service.ipmonitoring.IpMonitoringService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
@Slf4j
public class AdminController {

    private final AdminService adminService;
    private final IpMonitoringService ipMonitoringService;
    private final AuditService auditService;
    private final AdminAnalyticsService adminAnalyticsService;

    @GetMapping("/users")
    public ResponseEntity<ApiResponse<PagedResponse<UserAdminResponse>>> getUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            UserFilterRequest filter,
            HttpServletRequest request
    ) {
        log.info("AdminController.getUsers(): Started with page={} size={}", page, size);

        PagedResponse<UserAdminResponse> response = adminService.getUsers(page, size, filter);

        ApiResponse<PagedResponse<UserAdminResponse>> body = ApiResponse.success(
                "USERS_FETCHED",
                "Users fetched successfully",
                response,
                request.getRequestURI()
        );

        return ResponseEntity.ok(body);
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
    public ResponseEntity<ApiResponse<Void>> blockUser(@PathVariable Long id, HttpServletRequest request) {

        log.info("AdminController.blockUser(): Blocking id={}", id);
        adminService.blockUser(id);

        ApiResponse<Void> body = ApiResponse.success(
                "USER_BLOCKED",
                "User blocked successfully",
                null,
                request.getRequestURI()
        );

        return ResponseEntity.ok(body);
    }

    @PatchMapping("/users/{id}/unblock")
    public ResponseEntity<ApiResponse<Void>> unblockUser(@PathVariable Long id, HttpServletRequest request) {

        log.info("AdminController.unblockUser(): Unblocking id={}", id);
        adminService.unblockUser(id);

        ApiResponse<Void> body = ApiResponse.success(
                "USER_UNBLOCKED",
                "User unblocked successfully",
                null,
                request.getRequestURI()
        );

        return ResponseEntity.ok(body);
    }

    @GetMapping("/users/login-activity")
    public ResponseEntity<ApiResponse<PagedResponse<LoginActivityResponse>>> getLoginActivities(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            LoginActivityFilterRequest filter,
            HttpServletRequest request
    ) {
        log.info("AdminController.getLoginActivities(): page={} size={}", page, size);

        PagedResponse<LoginActivityResponse> response =
                adminService.getLoginActivities(page, size, filter);

        ApiResponse<PagedResponse<LoginActivityResponse>> body = ApiResponse.success(
                "LOGIN_ACTIVITIES_FETCHED",
                "Login activities fetched successfully",
                response,
                request.getRequestURI()
        );

        return ResponseEntity.ok(body);
    }


    @GetMapping("/users/login-activity/{id}")
    public ResponseEntity<ApiResponse<LoginActivityResponse>> getActivityById(HttpServletRequest request, @PathVariable Long id) {

        LoginActivityResponse activityById = adminService.getActivityById(id);

        ApiResponse<LoginActivityResponse> body = ApiResponse.success(
                "LOGIN_ACTIVITY_BY_ID_FETCHED",
                "Login activity for id=" + id,
                activityById,
                request.getRequestURI());

        return ResponseEntity.ok(body);
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

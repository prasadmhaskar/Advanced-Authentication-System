package com.pnm.auth.controller;

import com.pnm.auth.dto.request.LoginActivityFilterRequest;
import com.pnm.auth.dto.request.UserFilterRequest;
import com.pnm.auth.dto.response.ApiResponse;
import com.pnm.auth.dto.response.LoginActivityResponse;
import com.pnm.auth.dto.response.PagedResponse;
import com.pnm.auth.dto.response.UserAdminResponse;
import com.pnm.auth.service.AdminService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
@Slf4j
public class AdminController {

    private final AdminService adminService;

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
}





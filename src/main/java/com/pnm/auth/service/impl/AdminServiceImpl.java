package com.pnm.auth.service.impl;

import com.pnm.auth.dto.request.LoginActivityFilterRequest;
import com.pnm.auth.dto.request.UserFilterRequest;
import com.pnm.auth.dto.response.LoginActivityResponse;
import com.pnm.auth.dto.response.PagedResponse;
import com.pnm.auth.dto.response.UserAdminResponse;
import com.pnm.auth.entity.LoginActivity;
import com.pnm.auth.entity.User;
import com.pnm.auth.entity.UserIpLog;
import com.pnm.auth.enums.AuditAction;
import com.pnm.auth.exception.ResourceNotFoundException;
import com.pnm.auth.exception.UserNotFoundException;
import com.pnm.auth.repository.LoginActivityRepository;
import com.pnm.auth.repository.UserIpLogRepository;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.service.AdminService;
import com.pnm.auth.specification.LoginActivitySpecification;
import com.pnm.auth.specification.UserSpecification;
import com.pnm.auth.util.Audit;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.Caching;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AdminServiceImpl implements AdminService {

    private final UserRepository userRepository;
    private final LoginActivityRepository loginActivityRepository;

    // ============================================================
    //  1. GET USERS WITH FILTERS + PAGINATION
    // ============================================================
    @Override
    @Transactional(readOnly = true)
    @Cacheable(value = "users.list", key = "#page + '-' + #size + '-' + #filter")
    public PagedResponse<UserAdminResponse> getUsers(int page, int size, UserFilterRequest filter) {

        log.info("AdminService.getUsers(): started page={} size={}", page, size);

        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());

        Page<User> userPage = userRepository.findAll(
                UserSpecification.filter(filter),
                pageable
        );

        List<UserAdminResponse> content = userPage.getContent()
                .stream()
                .map(UserAdminResponse::fromEntity)
                .toList();

        log.info("AdminService.getUsers(): fetched {} users", content.size());

        return PagedResponse.<UserAdminResponse>builder()
                .content(content)
                .page(userPage.getNumber())
                .size(userPage.getSize())
                .totalElements(userPage.getTotalElements())
                .totalPages(userPage.getTotalPages())
                .last(userPage.isLast())
                .build();
    }


    // ============================================================
    //  2. DELETE USER
    // ============================================================
    @Override
    @Transactional
    @CacheEvict(value = {"users.list", "users"}, allEntries = true)
    @Audit(action = AuditAction.ADMIN_DELETE_USER, description = "Admin deleted a user")
    public void deleteUser(Long id) {

        log.info("AdminService.deleteUser(): started for id={}", id);

        User user = userRepository.findById(id)
                .orElseThrow(() -> {
                    log.warn("AdminService.deleteUser(): user not found id={}", id);
                    return new UserNotFoundException("User not found with id=" + id);
                });

        userRepository.delete(user);

        log.info("AdminService.deleteUser(): deleted user id={}", id);

    }


    // ============================================================
    //  3. BLOCK USER
    // ============================================================
    @Override
    @Transactional
    @Caching(evict = {
            @CacheEvict(value = "users", allEntries = true),
            @CacheEvict(value = "users.list", allEntries = true)
    })
    @Audit(action = AuditAction.ADMIN_BLOCK_USER, description = "Admin blocked a user")
    public void blockUser(Long id) {

        log.info("AdminService.blockUser(): started id={}", id);

        User user = userRepository.findById(id)
                .orElseThrow(() -> {
                    log.warn("AdminService.blockUser(): user not found id={}", id);
                    return new UserNotFoundException("User not found with id=" + id);
                });

        if (!user.isActive()) {
            log.info("AdminService.blockUser(): user already blocked id={}", id);
            return;
        }

        user.setActive(false);
        userRepository.save(user);

        log.info("AdminService.blockUser(): user blocked id={}", id);

    }


    // ============================================================
    //  4. UNBLOCK USER
    // ============================================================
    @Override
    @Transactional
    @Caching(evict = {
            @CacheEvict(value = "users", allEntries = true),
            @CacheEvict(value = "users.list", allEntries = true)
    })
    @Audit(action = AuditAction.ADMIN_UNBLOCK_USER, description = "Admin unblocked a user")
    public void unblockUser(Long id) {

        log.info("AdminService.unblockUser(): started id={}", id);

        User user = userRepository.findById(id)
                .orElseThrow(() -> {
                    log.warn("AdminService.unblockUser(): user not found id={}", id);
                    return new UserNotFoundException("User not found with id=" + id);
                });

        if (user.isActive()) {
            log.info("AdminService.unblockUser(): user already active id={}", id);
            return;
        }

        user.setActive(true);
        userRepository.save(user);

        log.info("AdminService.unblockUser(): user unblocked id={}", id);

    }


    // ============================================================
    //  5. LOGIN ACTIVITY LIST
    // ============================================================
    @Override
    @Transactional(readOnly = true)
    @Cacheable(value = "loginActivities", key = "#page + '-' + #size + '-' + #filter")
    public PagedResponse<LoginActivityResponse> getLoginActivities(
            int page,
            int size,
            LoginActivityFilterRequest filter
    ) {

        log.info("AdminService.getLoginActivities(): started page={} size={}", page, size);

        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());

        Page<LoginActivity> activityPage = loginActivityRepository.findAll(
                LoginActivitySpecification.filter(filter),
                pageable
        );

        List<LoginActivityResponse> content = activityPage.getContent()
                .stream()
                .map(LoginActivityResponse::fromEntity)
                .toList();

        log.info("AdminService.getLoginActivities(): fetched {} records", content.size());

        return PagedResponse.<LoginActivityResponse>builder()
                .content(content)
                .page(activityPage.getNumber())
                .size(activityPage.getSize())
                .totalElements(activityPage.getTotalElements())
                .totalPages(activityPage.getTotalPages())
                .last(activityPage.isLast())
                .build();
    }


    // ============================================================
    //  6. GET SINGLE LOGIN ACTIVITY BY ID
    // ============================================================
    @Override
    @Transactional(readOnly = true)
    @Cacheable(value = "loginActivity", key = "#id")
    public LoginActivityResponse getActivityById(Long id) {

        log.info("AdminService.getActivityById(): started id={}", id);

        LoginActivity activity = loginActivityRepository.findById(id)
                .orElseThrow(() -> {
                    log.warn("AdminService.getActivityById(): not found id={}", id);
                    return new ResourceNotFoundException("Login activity not found with id=" + id);
                });

        log.info("AdminService.getActivityById(): returned id={}", id);

        return LoginActivityResponse.fromEntity(activity);
    }
}
package com.pnm.auth.service.impl.admin;

import com.pnm.auth.dto.request.LoginActivityFilterRequest;
import com.pnm.auth.dto.request.UserFilterRequest;
import com.pnm.auth.dto.response.LoginActivityResponse;
import com.pnm.auth.dto.response.PagedResponse;
import com.pnm.auth.dto.response.UserAdminResponse;
import com.pnm.auth.domain.entity.LoginActivity;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuditAction;
import com.pnm.auth.exception.custom.ResourceNotFoundException;
import com.pnm.auth.exception.custom.UserNotFoundException;
import com.pnm.auth.repository.*;
import com.pnm.auth.service.admin.AdminService;
import com.pnm.auth.service.auth.UserPersistenceService;
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
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class AdminServiceImpl implements AdminService {


    private final UserRepository userRepository;
    private final LoginActivityRepository loginActivityRepository;
    private final UserPersistenceService userPersistenceService;

    public record UnblockUserResult(String code, String message) {
    }

    public record BlockUserResult(String code, String message) {
    }

    // ============================================================
    //  1. GET USERS WITH FILTERS + PAGINATION
    // ============================================================
    @Override
    @Transactional(readOnly = true)
    @Cacheable(value = "users.list", key = "#page + '-' + #size + '-' + #filter")
    public PagedResponse<UserAdminResponse> getAllUsers(UserFilterRequest filter, Pageable pageable) {
        log.info("Admin: Fetching users with filter={}", filter);

        // 1. Create Specification from Request
        Specification<User> spec = UserSpecification.getFilter(filter);

        // 2. Fetch Page from DB
        Page<User> userPage = userRepository.findAll(spec, pageable);

        // 3. Map Entity -> DTO and Wrap in PagedResponse
        // Assuming PagedResponse has a constructor or static method that takes a Spring Page
        return PagedResponse.of(userPage.map(UserAdminResponse::from));
    }


    // ============================================================
    //  2. DELETE USER
    // ============================================================
    @Override
    @Transactional
    @CacheEvict(value = {"users.list", "users"}, allEntries = true)
    @Audit(action = AuditAction.ADMIN_DELETE_USER, description = "Admin deleted a user", targetUserArgIndex = 0)
    public void deleteUser(Long id) {

        log.info("AdminService.deleteUser(): started for id={}", id);

        userRepository.findById(id).orElseThrow(() -> {
                    log.warn("AdminService.deleteUser(): user not found id={}", id);
                    return new UserNotFoundException("User not found with id=" + id);
                });

        userPersistenceService.deleteUserPermanently(id);

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
    @Audit(action = AuditAction.ADMIN_BLOCK_USER, description = "Admin blocked a user", targetUserArgIndex = 0)
    public BlockUserResult blockUser(Long id) {

        log.info("AdminService.blockUser(): started id={}", id);

        User user = userRepository.findById(id)
                .orElseThrow(() -> {
                    log.warn("AdminService.blockUser(): user not found id={}", id);
                    return new UserNotFoundException("User not found with id=" + id);
                });

        if (!user.isActive()) {
            log.info("AdminService.blockUser(): user is already blocked id={}", id);
            return new BlockUserResult("USER_ALREADY_BLOCKED", "User is already blocked");
        }

        user.setActive(false);
        userRepository.save(user);

        log.info("AdminService.blockUser(): user blocked successfully id={}", id);
        return new BlockUserResult("USER_BLOCKED", "User blocked successfully");

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
    @Audit(action = AuditAction.ADMIN_UNBLOCK_USER, description = "Admin unblocked a user", targetUserArgIndex = 0)
    public UnblockUserResult unblockUser(Long id) {

        log.info("AdminService.unblockUser(): started id={}", id);

        User user = userRepository.findById(id)
                .orElseThrow(() -> {
                    log.warn("AdminService.unblockUser(): user not found id={}", id);
                    return new UserNotFoundException("User not found with id=" + id);
                });

        if (user.isActive()) {

            log.info("AdminService.unblockUser(): user is already unblocked id={}", id);
            return new UnblockUserResult("USER_ALREADY_UNBLOCKED", "User is already unblocked");
        }

        user.setActive(true);
        userRepository.save(user);

        log.info("AdminService.unblockUser(): user unblocked successfully id={}", id);
        return new UnblockUserResult("USER_UNBLOCKED", "User unblocked successfully");

    }


    // ============================================================
    //  5. LOGIN ACTIVITY LIST
    // ============================================================
    @Override
    @Transactional(readOnly = true)
    // ⚠️ Caution: Caching lists with complex filters is hard to invalidate efficiently.
    // If real-time accuracy is critical, remove @Cacheable here or use a short TTL.
    @Cacheable(value = "loginActivities", key = "#page + '-' + #size + '-' + #filter.hashCode()")
    public PagedResponse<LoginActivityResponse> getLoginActivities(
            int page,
            int size,
            LoginActivityFilterRequest filter
    ) {
        log.info("AdminService.getLoginActivities(): page={} size={} filter={}", page, size, filter);

        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());

        Page<LoginActivity> activityPage = loginActivityRepository.findAll(
                LoginActivitySpecification.getFilter(filter), // Ensure Spec class name matches
                pageable
        );

        List<LoginActivityResponse> content = activityPage.getContent()
                .stream()
                .map(LoginActivityResponse::fromEntity)
                .toList();

        return PagedResponse.<LoginActivityResponse>builder()
                .content(content)
                .page(activityPage.getNumber())
                .size(activityPage.getSize())
                .totalElements(activityPage.getTotalElements())
                .totalPages(activityPage.getTotalPages())
                .last(activityPage.isLast())
                .build();
    }

    @Override
    @Transactional(readOnly = true)
    @Cacheable(value = "loginActivity", key = "#id")
    public LoginActivityResponse getActivityById(Long id) {
        log.info("AdminService.getActivityById(): fetching id={}", id);

        LoginActivity activity = loginActivityRepository.findById(id)
                .orElseThrow(() -> {
                    log.warn("AdminService.getActivityById(): not found id={}", id);
                    return new ResourceNotFoundException("Login activity not found with id=" + id);
                });

        return LoginActivityResponse.fromEntity(activity);
    }
}
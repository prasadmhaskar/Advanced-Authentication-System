package com.pnm.auth.service.impl.admin;

import com.pnm.auth.dto.request.LoginActivityFilterRequest;
import com.pnm.auth.dto.request.UserFilterRequest;
import com.pnm.auth.dto.response.UserActivityResponse;
import com.pnm.auth.dto.response.PagedResponse;
import com.pnm.auth.dto.response.UserAdminResponse;
import com.pnm.auth.domain.entity.UserActivity;
import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuditAction;
import com.pnm.auth.exception.custom.ResourceNotFoundException;
import com.pnm.auth.exception.custom.UserNotFoundException;
import com.pnm.auth.repository.*;
import com.pnm.auth.service.interfaces.admin.AdminService;
import com.pnm.auth.service.interfaces.auth.UserPersistenceService;
import com.pnm.auth.service.interfaces.auth.UserValidationService;
import com.pnm.auth.service.impl.cache.CacheManagementService;
import com.pnm.auth.specification.UserActivitySpecification;
import com.pnm.auth.specification.UserSpecification;
import com.pnm.auth.util.Audit;
import com.pnm.auth.util.MaskingUtil;
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

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class AdminServiceImpl implements AdminService {


    private final UserRepository userRepository;
    private final UserActivityRepository userActivityRepository;
    private final UserPersistenceService userPersistenceService;
    private final CacheManagementService cacheManagementService;
    private final UserValidationService userValidationService;
    private static final String USER_NOT_FOUND = "User not found with id=";

    public record UnblockUserResult(String code, String message) {}

    public record BlockUserResult(String code, String message) {}

    public record CreateAdminResult(String code, String message) {}

    // Get all users with filters + pagination
    @Override
    @Transactional(readOnly = true)
    @Cacheable(value = "users.list", key = "#page + '-' + #size + '-' + #filter")
    public PagedResponse<UserAdminResponse> getAllUsers(UserFilterRequest filter, Pageable pageable) {
        log.info("Admin: Fetching users with filter={}", filter);

        // Create Specification from Request
        Specification<User> spec = UserSpecification.getFilter(filter);

        // Fetch Page from DB
        Page<User> userPage = userRepository.findAll(spec, pageable);

        // Map Entity -> DTO and Wrap in PagedResponse
        return PagedResponse.of(userPage.map(UserAdminResponse::from));
    }


    // Delete user
    @Override
    @Transactional
    @CacheEvict(value = {"users.list", "users"}, allEntries = true)
    @Audit(action = AuditAction.ADMIN_DELETE_USER, description = "Admin deleted a user", targetUserArgIndex = 0)
    public void deleteUser(Long id) {

        log.info("AdminService.deleteUser(): started for id={}", id);

        User user = userRepository.findById(id).orElseThrow(() -> {
            log.warn("AdminService.deleteUser(): user not found id={}", id);
            return new UserNotFoundException(USER_NOT_FOUND + id);
        });

        cacheManagementService.evictUserFromCache(user.getEmail());

        userPersistenceService.deleteUserPermanently(id);

        log.info("AdminService.deleteUser(): deleted user id={}", id);
    }


    // Block user
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
                    return new UserNotFoundException(USER_NOT_FOUND + id);
                });

        if (!user.isActive()) {
            log.info("AdminService.blockUser(): user is already blocked id={}", id);
            return new BlockUserResult("USER_ALREADY_BLOCKED", "User is already blocked");
        }

        user.incrementTokenVersion();
        user.setActive(false);
        userRepository.save(user);

        // Delete user details from cache
        cacheManagementService.evictUserFromCache(user.getEmail());

        log.info("AdminService.blockUser(): user blocked successfully id={}", id);
        return new BlockUserResult("USER_BLOCKED", "User blocked successfully");

    }


    // Unblock user
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
                    return new UserNotFoundException(USER_NOT_FOUND + id);
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


    // User activity list
    @Override
    @Transactional(readOnly = true)
    @Cacheable(value = "userActivities", key = "#page + '-' + #size + '-' + #filter.hashCode()")
    public PagedResponse<UserActivityResponse> getUserActivities(
            int page,
            int size,
            LoginActivityFilterRequest filter
    ) {
        log.info("AdminService.getUserActivities(): page={} size={} filter={}", page, size, filter);

        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());

        Page<UserActivity> activityPage = userActivityRepository.findAll(
                UserActivitySpecification.getFilter(filter), // Ensure Spec class name matches
                pageable
        );

        List<UserActivityResponse> content = activityPage.getContent()
                .stream()
                .map(UserActivityResponse::fromEntity)
                .toList();

        return PagedResponse.<UserActivityResponse>builder()
                .content(content)
                .page(activityPage.getNumber())
                .size(activityPage.getSize())
                .totalElements(activityPage.getTotalElements())
                .totalPages(activityPage.getTotalPages())
                .last(activityPage.isLast())
                .build();
    }

    // Get user activity by activity id
    @Override
    @Transactional(readOnly = true)
    @Cacheable(value = "userActivity", key = "#id")
    public UserActivityResponse getActivityById(Long id) {
        log.info("AdminService.getActivityById(): fetching id={}", id);

        UserActivity activity = userActivityRepository.findById(id)
                .orElseThrow(() -> {
                    log.warn("AdminService.getActivityById(): not found id={}", id);
                    return new ResourceNotFoundException("User activity not found with activity id=" + id);
                });

        return UserActivityResponse.fromEntity(activity);
    }

    // Promote normal user to admin
    @Override
    @Transactional
    public CreateAdminResult createAdmin(String rawEmail){

        String email = rawEmail.trim().toLowerCase();

        log.info("AdminService.createAdmin(): Started for email={}", MaskingUtil.maskEmail(email));

        User user = userRepository.findByEmail(email).orElseThrow(() -> {
            log.warn("AdminService.createAdmin(): User not found with email={}", MaskingUtil.maskEmail(email));
            return new UserNotFoundException("User not found with email=" + email);
        });

        try {
            userValidationService.validateUserStatus(user);
        } catch (RuntimeException ex) {
            log.warn("AdminService.createAdmin(): Validation failed for user with email={}", MaskingUtil.maskEmail(email));
            throw ex;
        }

        if (user.getRoles().contains("ROLE_ADMIN")){
            log.warn("AdminService.createAdmin(): User is already admin");
            return new CreateAdminResult("ALREADY_ADMIN", "User is already admin");
        }

        List<String> updatedRoles = new ArrayList<>(user.getRoles());
        updatedRoles.add("ROLE_ADMIN");
        user.setRoles(updatedRoles);

        userRepository.save(user);

        cacheManagementService.evictUserFromCache(email);

        log.info("AdminService.createAdmin(): Started for email={}", MaskingUtil.maskEmail(email));

        return new CreateAdminResult("ADMIN_CREATED", "User with email= " +email+ " has been successfully appointed as ADMIN");

    }
}
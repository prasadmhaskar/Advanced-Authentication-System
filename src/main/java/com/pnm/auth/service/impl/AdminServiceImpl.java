package com.pnm.auth.service.impl;

import com.pnm.auth.dto.request.LoginActivityFilterRequest;
import com.pnm.auth.dto.request.UserFilterRequest;
import com.pnm.auth.dto.response.LoginActivityResponse;
import com.pnm.auth.dto.response.PagedResponse;
import com.pnm.auth.dto.response.UserAdminResponse;
import com.pnm.auth.entity.LoginActivity;
import com.pnm.auth.entity.User;
import com.pnm.auth.exception.ResourceNotFoundException;
import com.pnm.auth.exception.UserNotFoundException;
import com.pnm.auth.repository.LoginActivityRepository;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.service.AdminService;
import com.pnm.auth.specification.LoginActivitySpecification;
import com.pnm.auth.specification.UserSpecification;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class AdminServiceImpl implements AdminService {

    private final UserRepository userRepository;
    private final LoginActivityRepository loginActivityRepository;

    @Override
    @Transactional(readOnly = true)
    public PagedResponse<UserAdminResponse> getUsers(int page, int size, UserFilterRequest filter) {

        Pageable pageable = PageRequest.of(page, size);

        Page<User> userPage = userRepository.findAll(
                UserSpecification.filter(filter),
                pageable
        );

        List<UserAdminResponse> content = userPage.getContent()
                .stream()
                .map(UserAdminResponse::fromEntity)
                .toList();

        return PagedResponse.<UserAdminResponse>builder()
                .content(content)
                .page(userPage.getNumber())
                .size(userPage.getSize())
                .totalElements(userPage.getTotalElements())
                .totalPages(userPage.getTotalPages())
                .last(userPage.isLast())
                .build();
    }


    @Override
    @Transactional
    public void deleteUser(Long id) {
        if (!userRepository.existsById(id)) {
            log.warn("AdminService.deleteUser(): User not found with id={}", id);
            throw new UserNotFoundException("User not found");
        }
        userRepository.deleteById(id);
        log.info("AdminService.deleteUser(): User deleted successfully with id={}", id);
    }


    @Override
    @Transactional
    public void blockUser(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        user.setActive(false);
        userRepository.save(user);

        log.info("AdminService.blockUser(): User blocked id={}", id);
    }

    @Override
    @Transactional
    public void unblockUser(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        user.setActive(true);
        userRepository.save(user);

        log.info("AdminService.unblockUser(): User unblocked id={}", id);
    }


    @Transactional(readOnly = true)
    @Override
    public PagedResponse<LoginActivityResponse> getLoginActivities(
            int page,
            int size,
            LoginActivityFilterRequest filter
    ) {

        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());

        Page<LoginActivity> activityPage = loginActivityRepository.findAll(
                LoginActivitySpecification.filter(filter),
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



    @Transactional
    @Override
    public LoginActivityResponse getActivityById(Long id) {

        log.info("AdminService.getActivityById(): started");

        LoginActivity activity = loginActivityRepository.findById(id).orElseThrow(() ->{
            log.warn("AdminService.getActivityById(): no activity found for id={}",id);
            throw new ResourceNotFoundException("Login activity not found");
        });

        log.info("AdminService.getActivityById(): returned activity for id={}",id);
        return LoginActivityResponse.fromEntity(activity);
    }


}

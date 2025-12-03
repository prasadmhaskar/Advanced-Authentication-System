package com.pnm.auth.repository;

import com.pnm.auth.entity.LoginActivity;
import com.pnm.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

import java.util.List;

public interface LoginActivityRepository extends JpaRepository<LoginActivity, Long> , JpaSpecificationExecutor<LoginActivity> {
    List<LoginActivity> findByUserId(Long userId);
}

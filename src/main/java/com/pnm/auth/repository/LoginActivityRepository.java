package com.pnm.auth.repository;

import com.pnm.auth.domain.entity.LoginActivity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import java.util.List;
@Repository
public interface LoginActivityRepository extends JpaRepository<LoginActivity, Long> , JpaSpecificationExecutor<LoginActivity> {
    List<LoginActivity> findByUserId(Long userId);
}

package com.pnm.auth.repository;

import com.pnm.auth.domain.entity.UserActivity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface UserActivityRepository extends JpaRepository<UserActivity, Long> , JpaSpecificationExecutor<UserActivity> {
    void deleteByUserId(Long userId);
}

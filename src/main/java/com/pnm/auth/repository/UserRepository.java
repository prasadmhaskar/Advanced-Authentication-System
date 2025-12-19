package com.pnm.auth.repository;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.domain.enums.AuthProviderType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long>, JpaSpecificationExecutor<User> {

    Optional<User> findByEmail(String email);

    @Query("SELECT COUNT(u) FROM User u")
    long countAllUsers();

    @Query("SELECT COUNT(u) FROM User u WHERE u.active = true")
    long countActiveUsers();

    @Query("SELECT COUNT(u) FROM User u WHERE u.active = false")
    long countBlockedUsers();

    @Query("SELECT COUNT(u) FROM User u WHERE u.mfaEnabled = true")
    long countMfaEnabledUsers();

    @Query("SELECT COUNT(u) FROM User u WHERE u.createdAt >= :start")
    long countUsersCreatedAfter(LocalDateTime start);

}

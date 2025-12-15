package com.pnm.auth.repository;

import com.pnm.auth.domain.entity.TrustedDevice;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface TrustedDeviceRepository extends JpaRepository<TrustedDevice, Long> {

    boolean existsByUserIdAndDeviceSignatureAndActiveTrue(Long userId, String deviceSignature);

    List<TrustedDevice> findByUserIdAndActiveTrue(Long userId);

    void deleteByUserIdAndDeviceSignatureNot(Long userId, String deviceSignature);

    @Modifying
    @Query("DELETE FROM TrustedDevice d WHERE d.userId = :userId AND d.deviceSignature <> :deviceSignature")
    void deleteAllExceptCurrent(@Param("userId") Long userId, @Param("deviceSignature") String deviceSignature);

}

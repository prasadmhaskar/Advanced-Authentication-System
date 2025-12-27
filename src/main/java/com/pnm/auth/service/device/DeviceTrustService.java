package com.pnm.auth.service.device;

import com.pnm.auth.dto.response.DeviceTrustResponse;
import com.pnm.auth.domain.enums.AuditAction;
import com.pnm.auth.util.Audit;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

public interface DeviceTrustService {

    List<DeviceTrustResponse> getTrustedDevices(Long userId);

    void removeDevice(Long userId, Long deviceId);

    void trustDevice(Long userId, String deviceSignature, String deviceName);

    @Transactional
    void removeAllExceptCurrent(Long userId, String currentDeviceSignature);

    boolean isTrusted(Long userId, String deviceSignature);
}


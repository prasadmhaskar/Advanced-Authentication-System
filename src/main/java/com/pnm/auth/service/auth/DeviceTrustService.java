package com.pnm.auth.service.auth;

import com.pnm.auth.dto.response.TrustedDeviceResponse;
import com.pnm.auth.entity.User;
import com.pnm.auth.enums.AuditAction;
import com.pnm.auth.util.Audit;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

public interface DeviceTrustService {

    List<TrustedDeviceResponse> getTrustedDevices(Long userId);

    @Audit(action = AuditAction.DEVICE_REMOVE, description = "Removing a trusted device")
    void removeDevice(Long userId, Long deviceId);

    @Audit(action = AuditAction.DEVICE_TRUST_ADD, description = "Trusting new device")
    void trustDevice(Long userId, String deviceSignature, String deviceName);

    @Transactional
    @Audit(action = AuditAction.DEVICE_REMOVE_OTHERS, description = "Removing all other devices except current")
    void removeAllExceptCurrent(Long userId, String currentDeviceSignature);

    boolean isTrusted(Long userId, String deviceSignature);
}


package com.pnm.auth.service.interfaces.device;

import com.pnm.auth.dto.response.DeviceTrustResponse;
import com.pnm.auth.domain.enums.AuditAction;
import com.pnm.auth.util.Audit;
import com.pnm.auth.web.context.RequestContext;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

public interface DeviceTrustService {

    List<DeviceTrustResponse> getTrustedDevices();

    void removeDevice(Long deviceId);

    void trustDevice(Long userId, String deviceSignature, String deviceName);

    @Transactional
    void removeAllExceptCurrent(RequestContext ctx);

    boolean isTrusted(Long userId, String deviceSignature);
}


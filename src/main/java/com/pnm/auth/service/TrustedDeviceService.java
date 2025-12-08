package com.pnm.auth.service;

import com.pnm.auth.dto.response.TrustedDeviceResponse;

import java.util.List;

public interface TrustedDeviceService {

    List<TrustedDeviceResponse> getTrustedDevices(Long userId);

    void removeDevice(Long userId, Long deviceId);

    void trustDevice(Long userId, String deviceSignature, String deviceName);

    void removeAllExceptCurrent(Long userId, String currentDeviceSignature);

}

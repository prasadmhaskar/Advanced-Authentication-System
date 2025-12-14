package com.pnm.auth.service.impl;

import com.pnm.auth.dto.response.TrustedDeviceResponse;
import com.pnm.auth.entity.TrustedDevice;
import com.pnm.auth.enums.AuditAction;
import com.pnm.auth.exception.InvalidCredentialsException;
import com.pnm.auth.exception.ResourceNotFoundException;
import com.pnm.auth.repository.TrustedDeviceRepository;
import com.pnm.auth.service.TrustedDeviceService;
import com.pnm.auth.util.Audit;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class TrustedDeviceServiceImpl implements TrustedDeviceService {

    private final TrustedDeviceRepository trustedDeviceRepository;

    @Override
    public List<TrustedDeviceResponse> getTrustedDevices(Long userId) {
        return trustedDeviceRepository.findByUserIdAndActiveTrue(userId)
                .stream()
                .map(TrustedDeviceResponse::fromEntity)
                .toList();
    }

    @Override
    @Audit(action = AuditAction.DEVICE_REMOVE, description = "Removing a trusted device")
    public void removeDevice(Long userId, Long deviceId) {
        TrustedDevice device = trustedDeviceRepository.findById(deviceId)
                .orElseThrow(() -> new ResourceNotFoundException("Device not found"));

        if (!device.getUserId().equals(userId)) {
            throw new InvalidCredentialsException("You cannot remove this device");
        }

        device.setActive(false);
        trustedDeviceRepository.save(device);
    }

    @Override
    @Audit(action = AuditAction.DEVICE_TRUST_ADD, description = "Trusting new device")
    public void trustDevice(Long userId, String deviceSignature, String deviceName) {

        if (userId == null || deviceSignature == null || deviceSignature.isBlank()) {
            log.warn("TrustedDeviceService.trustDevice(): invalid params userId={} signature={}", userId, deviceSignature);
            return;
        }

        boolean exists = trustedDeviceRepository
                .existsByUserIdAndDeviceSignatureAndActiveTrue(userId, deviceSignature);

        if (exists) {
            log.info("TrustedDeviceService.trustDevice(): device already trusted userId={} signature={}", userId, deviceSignature);
            return;
        }

        TrustedDevice entity = TrustedDevice.builder()
                .userId(userId)
                .deviceSignature(deviceSignature)
                .deviceName(deviceName)
                .trustedAt(LocalDateTime.now())
                .active(true)
                .build();

        trustedDeviceRepository.save(entity);

        log.info("TrustedDeviceService.trustDevice(): new trusted device saved userId={} deviceName={}", userId, deviceName);
    }

    @Override
    @Transactional
    @Audit(action = AuditAction.DEVICE_REMOVE_OTHERS, description = "Removing all other devices except current")
    public void removeAllExceptCurrent(Long userId, String currentDeviceSignature) {

        if (userId == null || currentDeviceSignature == null) {
            log.warn("TrustedDeviceService.removeAllExceptCurrent(): invalid params");
            return;
        }

        log.info("TrustedDeviceService.removeAllExceptCurrent(): removing old devices for userId={} except={}",
                userId, currentDeviceSignature);

        trustedDeviceRepository.deleteAllExceptCurrent(userId, currentDeviceSignature);

        log.info("TrustedDeviceService.removeAllExceptCurrent(): completed userId={}", userId);
    }
}


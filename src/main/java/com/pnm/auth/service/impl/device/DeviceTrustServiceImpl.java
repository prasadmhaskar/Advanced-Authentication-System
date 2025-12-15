package com.pnm.auth.service.impl.device;

import com.pnm.auth.dto.response.DeviceTrustResponse;
import com.pnm.auth.domain.entity.TrustedDevice;
import com.pnm.auth.domain.enums.AuditAction;
import com.pnm.auth.exception.custom.InvalidCredentialsException;
import com.pnm.auth.exception.custom.ResourceNotFoundException;
import com.pnm.auth.repository.TrustedDeviceRepository;
import com.pnm.auth.service.device.DeviceTrustService;
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
public class DeviceTrustServiceImpl implements DeviceTrustService {
    private final TrustedDeviceRepository trustedDeviceRepository;

    @Override
    public List<DeviceTrustResponse> getTrustedDevices(Long userId) {
        return trustedDeviceRepository.findByUserIdAndActiveTrue(userId)
                .stream()
                .map(DeviceTrustResponse::fromEntity)
                .toList();
    }

    @Audit(action = AuditAction.DEVICE_REMOVE, description = "Removing a trusted device")
    @Override
    public void removeDevice(Long userId, Long deviceId) {
        TrustedDevice device = trustedDeviceRepository.findById(deviceId)
                .orElseThrow(() -> new ResourceNotFoundException("Device not found"));

        if (!device.getUserId().equals(userId)) {
            throw new InvalidCredentialsException("You cannot remove this device");
        }

        device.setActive(false);
        trustedDeviceRepository.save(device);
    }

    @Audit(action = AuditAction.DEVICE_TRUST_ADD, description = "Trusting new device")
    @Override
    public void trustDevice(Long userId, String deviceSignature, String deviceName) {

        try {
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
        }catch (Exception ex){
            log.error("TrustedDeviceService.trustDevice(): failed to trust device userId={} reason={}", userId, ex.getMessage(), ex);
        }
    }

    @Transactional
    @Audit(action = AuditAction.DEVICE_REMOVE_OTHERS, description = "Removing all other devices except current")
    @Override
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

    @Override
    public boolean isTrusted(Long userId, String deviceSignature) {
        try {
            return trustedDeviceRepository.existsByUserIdAndDeviceSignatureAndActiveTrue(userId, deviceSignature);
        } catch (Exception e) {
            log.error("DeviceTrustService: trust check failed userId={} reason={}", userId, e.getMessage(), e);
            return false; // if unknown → treat as not trusted
        }
    }
}

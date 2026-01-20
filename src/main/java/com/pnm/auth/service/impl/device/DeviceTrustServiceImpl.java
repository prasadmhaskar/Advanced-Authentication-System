package com.pnm.auth.service.impl.device;

import com.pnm.auth.dto.response.DeviceTrustResponse;
import com.pnm.auth.domain.entity.TrustedDevice;
import com.pnm.auth.event.SuccessEvent;
import com.pnm.auth.exception.custom.InvalidCredentialsException;
import com.pnm.auth.exception.custom.ResourceNotFoundException;
import com.pnm.auth.repository.RefreshTokenRepository;
import com.pnm.auth.repository.TrustedDeviceRepository;
import com.pnm.auth.service.impl.cache.CacheManagementService;
import com.pnm.auth.service.interfaces.device.DeviceTrustService;
import com.pnm.auth.util.AuthUtil;
import com.pnm.auth.util.JwtUtil;
import com.pnm.auth.util.UserAgentParser;
import com.pnm.auth.web.context.RequestContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class DeviceTrustServiceImpl implements DeviceTrustService {
    private final TrustedDeviceRepository trustedDeviceRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final ApplicationEventPublisher eventPublisher;
    private final CacheManagementService cacheManagementService;

    @Override
    public List<DeviceTrustResponse> getTrustedDevices() {
        log.info("DeviceTrustService.getTrustedDevices(): started");

        Long id = AuthUtil.getCurrentUserId();

        log.info("DeviceTrustService.getTrustedDevices() finished");
        return trustedDeviceRepository.findByUserIdAndActiveTrue(id)
                .stream()
                .map(DeviceTrustResponse::fromEntity)
                .toList();
    }

    @Override
    @Transactional
    public void removeDevice(Long deviceId, RequestContext ctx) {

        log.info("DeviceTrustService.removeDevice(): started");

        Long userId = AuthUtil.getCurrentUserId();
        TrustedDevice device = trustedDeviceRepository.findById(deviceId)
                .orElseThrow(() -> new ResourceNotFoundException("Device not found"));

        if (!device.getUserId().equals(userId)) {
            throw new InvalidCredentialsException("You cannot remove this device");
        }

        device.setActive(false);
        trustedDeviceRepository.save(device);

        refreshTokenRepository.invalidateByDeviceSignature(userId, device.getDeviceSignature());

        String email = AuthUtil.getCurrentEmail();
        cacheManagementService.evictUserFromCache(email);

        eventPublisher.publishEvent(new SuccessEvent(userId, null, ctx.ip(), ctx.userAgent(), "User removed device with deviceId: "+deviceId));

        log.info("DeviceTrustService.removeDevice(): finished");
    }

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
    @Override
    public void removeAllExceptCurrent(RequestContext ctx) {

        log.info("DeviceTrustService.removeAllExceptCurrent(): started");

        String currentDeviceSignature = UserAgentParser
                .parse(ctx.userAgent())
                .getSignature();

        Long userId = AuthUtil.getCurrentUserId();

        if (userId == null || currentDeviceSignature == null) {
            log.warn("TrustedDeviceService.removeAllExceptCurrent(): invalid params");
            return;
        }
        trustedDeviceRepository.deleteAllExceptCurrent(userId, currentDeviceSignature);

        refreshTokenRepository.invalidateAllExceptCurrentDevice(userId, currentDeviceSignature);

        String email = AuthUtil.getCurrentEmail();
        cacheManagementService.evictUserFromCache(email);

        eventPublisher.publishEvent(new SuccessEvent(userId, null, ctx.ip(), ctx.userAgent(), "User removed all devices except current"));

        log.info("DeviceTrustService.removeAllExceptCurrent(): finished and removed old devices for userId={} except={}",
                userId, currentDeviceSignature);
    }

    @Override
    public boolean isTrusted(Long userId, String deviceSignature) {
        try {
            return trustedDeviceRepository.existsByUserIdAndDeviceSignatureAndActiveTrue(userId, deviceSignature);
        } catch (Exception e) {
            log.error("DeviceTrustService: trust check failed userId={} reason={}", userId, e.getMessage(), e);
            return false;
        }
    }
}

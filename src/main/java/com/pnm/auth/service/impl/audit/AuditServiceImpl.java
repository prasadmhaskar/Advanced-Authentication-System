package com.pnm.auth.service.impl.audit;

import com.pnm.auth.dto.response.AuditLogResponse;
import com.pnm.auth.dto.response.PagedResponse;
import com.pnm.auth.domain.entity.AuditLog;
import com.pnm.auth.domain.enums.AuditAction;
import com.pnm.auth.repository.AuditLogRepository;
import com.pnm.auth.service.audit.AuditService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuditServiceImpl implements AuditService {

    private final AuditLogRepository repo;

    @Override
    public void record(AuditAction action,
                       Long actorUserId,
                       Long targetUserId,
                       String description,
                       String ip,
                       String userAgent) {

        AuditLog entry = AuditLog.builder()
                .action(action)
                .actorUserId(actorUserId)
                .targetUserId(targetUserId)
                .description(description)
                .ip(ip)
                .userAgent(userAgent)
                .createdAt(LocalDateTime.now())
                .build();

        repo.save(entry);

        log.info("AUDIT -> action={} actorUser={} targetUser={} desc={}",
                action, actorUserId, targetUserId, description);
    }

    @Transactional(readOnly = true)
    @Override
    public PagedResponse<AuditLogResponse> getAll(int page, int size) {

        log.info("AuditService.getAll(): page={} size={}", page, size);

        Pageable pageable = PageRequest.of(
                page,
                size,
                Sort.by("createdAt").descending()
        );

        Page<AuditLog> logs = repo.findAll(pageable);

        List<AuditLogResponse> list = logs.getContent()
                .stream()
                .map(AuditLogResponse::fromEntity)
                .toList();

        return new PagedResponse<>(
                list,
                logs.getNumber(),
                logs.getSize(),
                logs.getTotalElements(),
                logs.getTotalPages(),
                logs.isLast()
        );
    }

}



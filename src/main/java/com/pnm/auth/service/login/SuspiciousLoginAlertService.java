package com.pnm.auth.service.login;

import com.pnm.auth.domain.entity.User;

import java.util.List;

public interface SuspiciousLoginAlertService {
    void sendHighRiskAlert(User user, String ip, String userAgent, List<String> reasons);
}


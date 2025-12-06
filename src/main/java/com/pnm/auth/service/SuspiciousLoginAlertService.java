package com.pnm.auth.service;

import com.pnm.auth.entity.User;

import java.util.List;

public interface SuspiciousLoginAlertService {
    void sendHighRiskAlert(User user, String ip, String userAgent, List<String> reasons);
}


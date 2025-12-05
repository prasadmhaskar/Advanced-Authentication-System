package com.pnm.auth.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "user_ip_log")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserIpLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "ip_address", nullable = false, length = 100)
    private String ipAddress;

    @Column(name = "user_agent", columnDefinition = "TEXT")
    private String userAgent;

    @Column(name = "login_time", nullable = false)
    private LocalDateTime loginTime = LocalDateTime.now();

    @Column(name = "is_suspicious", nullable = false)
    private Boolean isSuspicious = false;

    @Column(name = "country_code", length = 10)
    private String countryCode;

    @Column(name = "city", length = 100)
    private String city;

    @Column(name = "risk_score")
    private Integer riskScore = 0;

    @Column(name = "risk_reason", length = 255)
    private String riskReason;

    @Column(name = "device_signature", length = 255)
    private String deviceSignature;

    @Column(name = "device_type", length = 50)
    private String deviceType; // e.g. DESKTOP, MOBILE, TABLET, BOT

    @Column(name = "device_name", length = 100)
    private String deviceName; // e.g. "Chrome on Windows", "Mobile Chrome on Android"

}


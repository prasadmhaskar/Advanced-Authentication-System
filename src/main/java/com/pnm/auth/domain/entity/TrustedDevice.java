package com.pnm.auth.domain.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "trusted_devices")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TrustedDevice {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Long userId;

    @Column(nullable = false)
    private String deviceSignature;    // hashed device fingerprint

    private String deviceName;

    private LocalDateTime trustedAt;

    private Boolean active = true;     // user can deactivate device
}


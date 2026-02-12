# 🛡️ Advanced Authentication & Security System

![Java](https://img.shields.io/badge/Java-17-orange?style=for-the-badge&logo=java)
![Spring Boot](https://img.shields.io/badge/Spring_Boot-3.2-green?style=for-the-badge&logo=spring)
![Security](https://img.shields.io/badge/Spring_Security-6.0-red?style=for-the-badge&logo=springsecurity)
![Redis](https://img.shields.io/badge/Redis-Caching_&_Rate_Limiting-red?style=for-the-badge&logo=redis)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-blue?style=for-the-badge&logo=postgresql)
![AWS](https://img.shields.io/badge/Deployment-AWS_EC2-orange?style=for-the-badge&logo=amazon-aws)

> **An enterprise-grade, high-security authentication platform engineered for scale, compliance, and resilience.**

---

## 🚀 Live Demo
**Swagger UI / API Documentation:**
👉 **[https://prasad-auth-sys.duckdns.org/swagger-ui/index.html](https://prasad-auth-sys.duckdns.org/swagger-ui/index.html)**

*(Note: Hosted on AWS EC2 t2.micro. First request may have slight latency due to cold start.)*

---

## 📖 Project Overview
This is not just a login form. This is a **hardened security framework** designed to mitigate OWASP Top 10 vulnerabilities. It features a custom-built stateless architecture using JWTs, aggressive Redis-backed rate limiting, and adaptive risk analysis based on geolocation and device fingerprinting.

### **Core Problem Solved**
Most auth systems fail under load or succumb to credential stuffing. This system implements **Defense-in-Depth**:
1.  **Layer 1 (Network):** Nginx & Redis Rate Limiting (DDoS protection).
2.  **Layer 2 (Identity):** Stateless JWT with rotation & blacklisting.
3.  **Layer 3 (Behavior):** IP & Device tracking to detect anomalies.

---

## 🏗️ System Architecture

```mermaid
graph TD
    %% Client Layer
    Client((Client/Consumer)) -->|REST/OAuth2| FilterChain[Spring Security Filter Chain]

    %% Filter Chain Details
    subgraph Filter_Chain [Hardened Security Pipeline]
        direction TB
        F1[RequestLoggingFilter - MDC/IP Context]
        F2[RedisRateLimiterFilter - DDoS Protection]
        F3[BlockHttpMethodsFilter - Protocol Hardening]
        F4[OAuthRedirectValidationFilter]
        F5[JwtAuthenticationFilter - Stateless Auth]
        F6[SecurityHeadersFilter - OWASP Compliance]
        
        F1 --> F2 --> F3 --> F4 --> F5 --> F6
    end

    FilterChain -->|Valid Request| Controllers{API Controllers}

    %% Logic Layer
    subgraph Controllers_Orchestrators [Business Logic Layer]
        Controllers -->|User Flows| AuthOrch[Auth Orchestrators]
        Controllers -->|Admin Flows| AdminService[Admin & Analytics Service]
        
        AuthOrch -->|Authn/Authz| Identity[Identity Service]
        AuthOrch -->|Security| RiskEngine[Adaptive Risk Engine]
        AdminService -->|Governance| Audit[Audit & IP Monitoring]
    end

    %% Persistence Layer
    subgraph Persistence_Layer [Data & Cache Layer]
        F2 -.->|Check/Incr| Redis[(Redis)]
        Identity -->|Session/Blacklist| Redis
        Identity -->|Users/Devices| Postgres[(PostgreSQL)]
        RiskEngine -->|Fingerprints| Postgres
        Audit -->|forensic Logs| Postgres
    end

    %% Error Handling
    Controllers -.->|Throws| GlobalEx[Global Exception Handler]
    FilterChain -.->|Fails| SecurityEx[AuthEntryPoint / AccessDeniedHandler]
    GlobalEx & SecurityEx -->|Unified Response| ApiResponse[JSON ApiResponse DTO]
    ApiResponse -->|Return| Client

    %% Styling
    style Filter_Chain fill:#f5f5f5,stroke:#333,stroke-dasharray: 5 5
    style Redis fill:#ffcccc,stroke:#b91d1d
    style Postgres fill:#d1fae5,stroke:#065f46
    style F5 fill:#dbeafe,stroke:#1e40af
    style ApiResponse fill:#fef3c7,stroke:#92400e
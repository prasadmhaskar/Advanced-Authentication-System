# 🛡️ Advanced Authentication & Security System

![Java](https://img.shields.io/badge/Java-17-orange?style=for-the-badge&logo=java)
![Spring Boot](https://img.shields.io/badge/Spring_Boot-3.2-green?style=for-the-badge&logo=spring)
![Spring Security](https://img.shields.io/badge/Spring_Security-6.0-red?style=for-the-badge&logo=springsecurity)
![Redis](https://img.shields.io/badge/Redis-Caching_&_Rate_Limiting-red?style=for-the-badge&logo=redis)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-blue?style=for-the-badge&logo=postgresql)
![AWS](https://img.shields.io/badge/Deployment-AWS_EC2-orange?style=for-the-badge&logo=amazon-aws)

> **An enterprise-grade, high-security authentication platform engineered for scale, compliance, and resilience.**

---

## 🚀 Live Demo & Documentation
**Interactive API Docs (Swagger UI):**
👉 **[https://prasad-auth-sys.duckdns.org/swagger-ui/index.html](https://prasad-auth-sys.duckdns.org/swagger-ui/index.html)**

### ⚡ Architectural Decision: Headless API
This system utilizes an **API-First Architecture** via Swagger UI to ensure absolute security transparency.
* **No UI Obfuscation:** Unlike traditional frontends that hide complexity, this exposes the raw API contract.
* **Security Validation:** Reviewers can directly inspect critical headers (HSTS, CSP), HttpOnly cookies, and JWT payloads.
* **Integration Ready:** The provided OpenAPI spec allows for immediate client generation in any language.

---

## 📖 Project Overview
This is **not just a login form**. It is a **hardened security framework** designed to mitigate OWASP Top 10 vulnerabilities. It features a custom-built stateless architecture using JWTs, aggressive Redis-backed rate limiting, and adaptive risk analysis based on geolocation and device fingerprinting.

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
```
## 🛡️ Key Security Features

### 🔐 Authentication & Authorization
* **Stateless JWT:** Signed using RS256 (Private/Public Key Pair).
* **Token Rotation:** Refresh tokens with reuse detection (prevents replay attacks).
* **RBAC (Role-Based Access Control):** Granular permissions for `USER`, `ADMIN`, and `SUPER_ADMIN`.
* **MFA (Multi-Factor Authentication):** Time-based OTP (TOTP) and Email-based verification.

### 🚫 Threat Mitigation
* **Rate Limiting (Redis + Bucket4j):**
    * *Public API:* 100 req/min
    * *Auth Endpoints:* 5 req/min (Brute-force protection)
* **Geo-Fencing:** Integration with **MaxMind GeoLite2** to detect impossible travel and suspicious logins.
* **Device Fingerprinting:** Tracks User-Agent and Client Hints to identify new/suspicious devices.

### ⚡ Performance Engineering
* **Redis Caching:** Distributed caching for user sessions and blacklisted tokens.
* **Async Processing:** Email sending and audit logging offloaded to virtual threads to prevent blocking.
* **Database Optimization:** Indexed columns for high-frequency queries (email, username).

---

## 🛠️ Tech Stack

| Component | Technology | Description |
| :--- | :--- | :--- |
| **Language** | Java 17 | Core logic and concurrency |
| **Framework** | Spring Boot 3.2 | Web MVC, DI, AOP |
| **Security** | Spring Security 6 | Filter chains, OAuth2 Resource Server |
| **Database** | PostgreSQL 15 | Relational data & JSONB support |
| **Cache** | Redis | Rate limiting buckets & Token blacklist |
| **Validation** | Hibernate Validator | JSR-380 Request DTO validation |
| **Deployment** | AWS EC2 (Linux) | Production environment |
| **Proxy** | Nginx | Reverse proxy, SSL termination, Load balancing |

---

## ⚙️ Local Setup & Installation

**Prerequisites:**
* Java 17+
* PostgreSQL running on port `5432`
* Redis running on port `6379`

### 1. Clone the Repository
```bash
git clone [https://github.com/YOUR_USERNAME/Advanced-Authentication-System.git](https://github.com/YOUR_USERNAME/Advanced-Authentication-System.git)
cd Advanced-Authentication-System
```
### 2. Configure Environment
* Update src/main/resources/application.properties with your database credentials:
* spring.datasource.url=jdbc:postgresql://localhost:5432/advanced_auth
* spring.datasource.username=postgres
* spring.datasource.password=your_password

### 3. Build and Run
* ./mvnw clean install
* ./mvnw spring-boot:run

### 4. Access the Application
* Swagger UI: http://localhost:8080/swagger-ui/index.html

---

## 👨💻 Author
* Name: Prasad Mhaskar
* Role: Backend Engineer | Java & Cloud Specialist
* Focus: Building scalable, secure distributed systems.
* LinkedIn: [https://www.linkedin.com/in/prasad-mhaskar/]












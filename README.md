# Advanced Authentication System

A production-style Identity and Access Management system built with Spring Boot 3, JDK 17, and PostgreSQL designed to handle the full lifecycle of secure user authentication and administrative governance.

🏗️ Architectural Excellence
🔹 **Orchestrator Pattern:** Business logic is abstracted into dedicated orchestrators, ensuring the Web layer remains thin and the system remains testable.
🔹 **Global Exception Framework:** A centralized `@RestControllerAdvice` ensures 100% consistent API contracts and prevents sensitive data leakage.

🛡️ Security & Observability Suite
🔹 **Stateless Auth + Rotation:** JWT-based session management with **Refresh Token Rotation** and a Redis-backed blacklist.
🔹 **Adaptive Risk Engine:** Monitors IP heuristics and Device Fingerprinting (User-Agent parsing) to trigger step-up MFA (OTP) upon anomaly detection.
🔹 **Admin SOC Lite:** Dedicated administrative suite for **IP Monitoring**, **Audit Trails**, and **User Lifecycle Governance** (Blocking/Unblocking/Analytics).
🔹 **Account Linking:** Automated conflict-resolution flow for linking Social OAuth2 providers (Google/GitHub) to existing local profiles.



🛠️ Getting Started
```bash
git clone [https://github.com/prasadmhaskar/Advanced-Authentication-System](https://github.com/prasadmhaskar/Advanced-Authentication-System)
docker-compose up --build

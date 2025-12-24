```mermaid
graph TB
    %% Client Layer
    Client((Client/Mobile/Web)) -->|REST API| Gateway[Spring Security Filter Chain]

    %% Security Layer
    subgraph Security_Engine [Security & Authentication Layer]
        Gateway -->|Stateless Auth| JWT[JWT & Refresh Token Rotation]
        Gateway -->|Rate Limiting| RateLimiter[Redis Rate Limiter]
        JWT -->|Blacklist Check| Redis_S[(Redis Cache)]
    end

    %% Logic Layer
    subgraph Logic_Layer [Business Logic - Orchestrators]
        Gateway -->|Delegates| AuthOrch[Auth Orchestrator]
        Gateway -->|Delegates| AdminOrch[Admin/SOC Orchestrator]
        
        AuthOrch -->|Heuristics| RiskEngine[Adaptive Risk Engine]
        AuthOrch -->|MFA Trigger| OTP[OTP/Email Service]
        
        AdminOrch -->|Forensics| IPMonitor[IP Monitoring Service]
        AdminOrch -->|Tracking| Audit[Audit Logging Service]
    end

    %% Data Layer
    subgraph Data_Persistence [Persistence Layer]
        RiskEngine -->|Device Trust| Postgres[(PostgreSQL)]
        Audit -->|Immutable Logs| Postgres
        AuthOrch -->|User Data| Postgres
    end

    %% Styling
    style Gateway fill:#f96,stroke:#333,stroke-width:2px
    style Security_Engine fill:#e1f5fe,stroke:#01579b
    style Logic_Layer fill:#fff3e0,stroke:#ff6f00
    style Redis_S fill:#ffcdd2
    style Postgres fill:#c8e6c9

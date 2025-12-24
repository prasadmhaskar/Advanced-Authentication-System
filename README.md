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

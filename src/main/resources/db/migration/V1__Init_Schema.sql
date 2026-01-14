-- V1__Init_Schema.sql (Long/BIGINT Edition)

-- 1. USERS TABLE
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255),
    email_verified BOOLEAN DEFAULT FALSE,
    active BOOLEAN DEFAULT TRUE,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    token_version INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_email ON users(email);

-- 1.1 USER_ROLES (Since you use @ElementCollection)
CREATE TABLE user_roles (
    user_id BIGINT NOT NULL,
    role VARCHAR(50) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 2. REFRESH TOKENS
CREATE TABLE user_refresh_tokens (
    id BIGSERIAL PRIMARY KEY,
    token VARCHAR(255) NOT NULL UNIQUE,
    user_id BIGINT NOT NULL,
    device_signature VARCHAR(255),
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    used BOOLEAN DEFAULT FALSE,
    invalidated BOOLEAN DEFAULT FALSE,
    CONSTRAINT fk_refresh_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_refresh_token_val ON user_refresh_tokens(token);

-- 3. OAUTH PROVIDERS
CREATE TABLE user_oauth_providers (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    provider_type VARCHAR(50) NOT NULL,
    provider_id VARCHAR(255) NOT NULL,
    linked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN DEFAULT TRUE,
    CONSTRAINT fk_oauth_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT uq_user_provider UNIQUE (user_id, provider_type) -- Enforced by Java but good in DB
);

CREATE INDEX idx_oauth_provider_id ON user_oauth_providers(provider_id);

-- 4. ACCOUNT LINK TOKENS
CREATE TABLE account_link_tokens (
    id BIGSERIAL PRIMARY KEY,
    token VARCHAR(100) NOT NULL UNIQUE,
    user_id BIGINT NOT NULL,
    provider_to_link VARCHAR(50) NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_link_token_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_link_token_val ON account_link_tokens(token);

-- 5. VERIFICATION TOKENS
CREATE TABLE verification_tokens (
    id BIGSERIAL PRIMARY KEY,
    token VARCHAR(255) NOT NULL UNIQUE,
    user_id BIGINT NOT NULL,
    type VARCHAR(50) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
    CONSTRAINT fk_verify_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_verify_token_val ON verification_tokens(token);

-- 6. MFA TOKENS
CREATE TABLE mfa_tokens (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    otp VARCHAR(10) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    risk_based BOOLEAN DEFAULT FALSE,
    CONSTRAINT fk_mfa_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 7. LOGIN ACTIVITY
CREATE TABLE login_activity (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT, -- Nullable
    email VARCHAR(255),
    ip_address VARCHAR(100),
    user_agent VARCHAR(255),
    status VARCHAR(50),
    message VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_login_activity_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX idx_login_activity_ip ON login_activity(ip_address);
CREATE INDEX idx_login_activity_email ON login_activity(email);

-- 8. TRUSTED DEVICES
CREATE TABLE trusted_devices (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL, -- Logical FK, not strictly enforced in your entity but good practice
    device_signature VARCHAR(255) NOT NULL,
    device_name VARCHAR(255),
    trusted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN DEFAULT TRUE
);

CREATE INDEX idx_trusted_device_sig ON trusted_devices(user_id, device_signature);

-- 9. USER IP LOGS
CREATE TABLE user_ip_log (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT,
    ip_address VARCHAR(100) NOT NULL,
    user_agent TEXT,
    login_time TIMESTAMP NOT NULL,
    is_suspicious BOOLEAN DEFAULT FALSE,
    country_code VARCHAR(10),
    city VARCHAR(100),
    risk_score INT DEFAULT 0,
    risk_reason VARCHAR(255),
    device_signature VARCHAR(255),
    device_type VARCHAR(50),
    device_name VARCHAR(100)
);

CREATE INDEX idx_ip_log_user_id ON user_ip_log(user_id);
CREATE INDEX idx_ip_log_ip ON user_ip_log(ip_address);

-- 10. AUDIT LOGS
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    actor_user_id BIGINT,
    target_user_id BIGINT,
    action VARCHAR(100),
    description VARCHAR(500),
    ip VARCHAR(100),
    user_agent VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
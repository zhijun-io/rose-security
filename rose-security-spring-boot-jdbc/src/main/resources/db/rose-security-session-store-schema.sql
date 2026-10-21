CREATE TABLE user_sessions (
    session_id VARCHAR(64) PRIMARY KEY,
    username VARCHAR(320) NOT NULL,
    security_version BIGINT NOT NULL,
    authenticated_at TIMESTAMP NOT NULL,
    authentication_methods VARCHAR(2048) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    last_used_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    absolute_expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP NULL,
    client_ip VARCHAR(128) NULL,
    device VARCHAR(256) NULL,
    current_refresh_token_hash VARCHAR(64) NULL
);

CREATE TABLE user_session_refresh_tokens (
    token_hash VARCHAR(64) PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL,
    consumed BOOLEAN NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    CONSTRAINT fk_user_session_refresh_tokens_session
        FOREIGN KEY (session_id) REFERENCES user_sessions(session_id)
);

CREATE INDEX idx_user_sessions_username ON user_sessions(username);
CREATE INDEX idx_user_session_refresh_tokens_session ON user_session_refresh_tokens(session_id);

-- A single coordination row makes first-session concurrency limits portable across JDBC databases.
CREATE TABLE user_session_creation_lock (
    lock_id INTEGER PRIMARY KEY
);

INSERT INTO user_session_creation_lock (lock_id) VALUES (1);

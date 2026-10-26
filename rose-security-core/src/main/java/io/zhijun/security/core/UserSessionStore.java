package io.zhijun.security.core;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

/** Persistence boundary for revocable token families and one-time refresh tokens. */
public interface UserSessionStore {

    /** Atomically persists a new session without a refresh token. */
    void create(UserSession session);

    /** Atomically persists a new session and its first refresh-token hash. */
    void create(UserSession session, String refreshTokenHash);

    /** Atomically applies the user's concurrency policy and creates a session if the policy permits it. */
    default SessionCreationResult create(
            UserSession session, String refreshTokenHash, UserSessionConcurrencyPolicy.Policy concurrencyPolicy) {
        if (concurrencyPolicy.maximumActiveSessions() > 0) {
            throw new IllegalStateException(
                    "UserSessionStore must implement atomic session limits when concurrency is enabled");
        }
        if (refreshTokenHash == null) {
            create(session);
        } else {
            create(session, refreshTokenHash);
        }
        return SessionCreationResult.CREATED;
    }

    /**
     * Atomically resolves the presented hash, consumes it, and installs its replacement. Re-presenting a consumed
     * token must revoke the entire active family and return {@link RotationStatus#REPLAYED}; implementations must not
     * install the supplied replacement in that case. Implementations must also reject revoked or expired families,
     * and cap the replacement expiry at the family's original absolute expiry.
     */
    RotationResult rotate(String presentedTokenHash, String replacementTokenHash, Duration refreshTtl, Instant now);

    boolean revoke(String sessionId, String username, Instant revokedAt);

    int revokeAll(String username, Instant revokedAt);

    List<UserSession> findActiveSessions(String username, Instant now);

    /** Authentication context is retained unchanged when the refresh-token family is rotated. */
    record UserSession(
            String sessionId,
            String username,
            long securityVersion,
            Instant authenticatedAt,
            List<String> authenticationMethods,
            Instant createdAt,
            Instant lastUsedAt,
            Instant expiresAt,
            Instant absoluteExpiresAt,
            Instant revokedAt,
            String clientIp,
            String device) {

        public UserSession {
            authenticationMethods = List.copyOf(authenticationMethods);
        }
    }

    record RotationResult(RotationStatus status, UserSession session) {}

    enum RotationStatus {
        ROTATED,
        REPLAYED,
        INVALID
    }

    enum SessionCreationResult {
        CREATED,
        LIMIT_REACHED
    }
}

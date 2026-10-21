package io.zhijun.security.sample;

import io.zhijun.security.core.UserSessionStore;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/** Volatile sample-only store. Never use this implementation in a deployed application. */
@Component
public class SampleUserSessionStore implements UserSessionStore {

    private final Map<String, UserSession> sessions = new HashMap<>();
    private final Map<String, StoredRefreshToken> refreshTokensByHash = new HashMap<>();

    @Override
    public synchronized void create(UserSession session) {
        if (sessions.containsKey(session.sessionId())) {
            throw new IllegalStateException("Token session collision");
        }
        sessions.put(session.sessionId(), session);
    }

    @Override
    public synchronized void create(UserSession session, String refreshTokenHash) {
        if (sessions.containsKey(session.sessionId()) || refreshTokensByHash.containsKey(refreshTokenHash)) {
            throw new IllegalStateException("Token session collision");
        }
        sessions.put(session.sessionId(), session);
        refreshTokensByHash.put(
                refreshTokenHash, new StoredRefreshToken(session.sessionId(), false, session.expiresAt()));
    }

    @Override
    public synchronized RotationResult rotate(
            String presentedTokenHash, String replacementTokenHash, Duration refreshTtl, Instant now) {
        StoredRefreshToken presented = refreshTokensByHash.get(presentedTokenHash);
        if (presented == null) {
            return new RotationResult(RotationStatus.INVALID, null);
        }
        UserSession current = sessions.get(presented.sessionId());
        if (current == null) {
            return new RotationResult(RotationStatus.INVALID, null);
        }
        if (presented.consumed()) {
            UserSession revoked = revoked(current, now);
            markSessionRevoked(revoked);
            return new RotationResult(RotationStatus.REPLAYED, revoked);
        }
        if (current.revokedAt() != null) {
            return new RotationResult(RotationStatus.INVALID, current);
        }
        if (!presented.expiresAt().isAfter(now) || !current.absoluteExpiresAt().isAfter(now)) {
            return new RotationResult(RotationStatus.INVALID, current);
        }
        Instant replacementExpiresAt = now.plus(refreshTtl);
        if (replacementExpiresAt.isAfter(current.absoluteExpiresAt())) {
            replacementExpiresAt = current.absoluteExpiresAt();
        }
        UserSession rotated = new UserSession(
                current.sessionId(),
                current.username(),
                current.securityVersion(),
                current.authenticatedAt(),
                current.authenticationMethods(),
                current.createdAt(),
                now,
                replacementExpiresAt,
                current.absoluteExpiresAt(),
                null,
                current.clientIp(),
                current.device());
        sessions.put(current.sessionId(), rotated);
        refreshTokensByHash.put(
                presentedTokenHash, new StoredRefreshToken(current.sessionId(), true, presented.expiresAt()));
        refreshTokensByHash.put(
                replacementTokenHash, new StoredRefreshToken(current.sessionId(), false, replacementExpiresAt));
        return new RotationResult(RotationStatus.ROTATED, rotated);
    }

    @Override
    public synchronized boolean revoke(String sessionId, String username, Instant revokedAt) {
        UserSession current = sessions.get(sessionId);
        if (current == null || !current.username().equals(username) || current.revokedAt() != null) {
            return false;
        }
        markSessionRevoked(revoked(current, revokedAt));
        return true;
    }

    @Override
    public synchronized int revokeAll(String username, Instant revokedAt) {
        List<String> sessionIds = sessions.values().stream()
                .filter(session -> session.username().equals(username) && session.revokedAt() == null)
                .map(UserSession::sessionId)
                .toList();
        sessionIds.forEach(sessionId -> revoke(sessionId, username, revokedAt));
        return sessionIds.size();
    }

    @Override
    public synchronized List<UserSession> findActiveSessions(String username, Instant now) {
        return sessions.values().stream()
                .filter(session -> session.username().equals(username)
                        && session.revokedAt() == null
                        && session.expiresAt().isAfter(now)
                        && session.absoluteExpiresAt().isAfter(now))
                .toList();
    }

    private void markSessionRevoked(UserSession session) {
        sessions.put(session.sessionId(), session);
        refreshTokensByHash.replaceAll((ignoredHash, token) -> {
            if (!token.sessionId().equals(session.sessionId())) {
                return token;
            }
            return new StoredRefreshToken(session.sessionId(), true, token.expiresAt());
        });
    }

    private static UserSession revoked(UserSession session, Instant revokedAt) {
        return new UserSession(
                session.sessionId(),
                session.username(),
                session.securityVersion(),
                session.authenticatedAt(),
                session.authenticationMethods(),
                session.createdAt(),
                session.lastUsedAt(),
                session.expiresAt(),
                session.absoluteExpiresAt(),
                revokedAt,
                session.clientIp(),
                session.device());
    }

    private record StoredRefreshToken(String sessionId, boolean consumed, Instant expiresAt) {}
}

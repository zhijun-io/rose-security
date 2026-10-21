package io.zhijun.security.session.jdbc;

import io.zhijun.security.core.UserSessionConcurrencyPolicy;
import io.zhijun.security.core.UserSessionStore;
import java.nio.charset.StandardCharsets;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/** JDBC persistence for token sessions; schema lifecycle remains owned by the application. */
public class JdbcUserSessionStore implements UserSessionStore {

    private static final RowMapper<UserSession> SESSION_MAPPER = JdbcUserSessionStore::mapSession;
    private static final int SESSION_CREATION_LOCK_ID = 1;

    private final JdbcTemplate jdbc;
    private final TransactionTemplate transactions;

    public JdbcUserSessionStore(JdbcTemplate jdbc, PlatformTransactionManager transactionManager) {
        this.jdbc = jdbc;
        this.transactions = new TransactionTemplate(transactionManager);
    }

    @Override
    public void create(UserSession session) {
        transactions.executeWithoutResult(status -> insertSession(session));
    }

    @Override
    public void create(UserSession session, String refreshTokenHash) {
        transactions.executeWithoutResult(status -> {
            insertSession(session);
            if (refreshTokenHash != null) {
                insertRefreshToken(session, refreshTokenHash);
            }
        });
    }

    @Override
    public SessionCreationResult create(
            UserSession session, String refreshTokenHash, UserSessionConcurrencyPolicy.Policy concurrencyPolicy) {
        if (concurrencyPolicy.maximumActiveSessions() == 0) {
            if (refreshTokenHash == null) {
                create(session);
            } else {
                create(session, refreshTokenHash);
            }
            return SessionCreationResult.CREATED;
        }
        return transactions.execute(status -> createWithLimit(session, refreshTokenHash, concurrencyPolicy));
    }

    private SessionCreationResult createWithLimit(
            UserSession session, String refreshTokenHash, UserSessionConcurrencyPolicy.Policy concurrencyPolicy) {
        lockLimitedSessionCreation();
        List<UserSession> activeSessions = jdbc.query(
                "SELECT * FROM user_sessions WHERE username = ? AND revoked_at IS NULL AND expires_at > ? AND absolute_expires_at > ? ORDER BY created_at ASC, session_id ASC FOR UPDATE",
                SESSION_MAPPER,
                session.username(),
                timestamp(session.createdAt()),
                timestamp(session.createdAt()));
        int maximum = concurrencyPolicy.maximumActiveSessions();
        if (activeSessions.size() >= maximum
                && concurrencyPolicy.limitBehavior() == UserSessionConcurrencyPolicy.LimitBehavior.DENY_NEW) {
            return SessionCreationResult.LIMIT_REACHED;
        }
        while (activeSessions.size() >= maximum) {
            revokeFamily(activeSessions.removeFirst(), session.createdAt());
        }
        insertSession(session);
        if (refreshTokenHash != null) {
            insertRefreshToken(session, refreshTokenHash);
        }
        return SessionCreationResult.CREATED;
    }

    private void lockLimitedSessionCreation() {
        jdbc.queryForObject(
                "SELECT lock_id FROM user_session_creation_lock WHERE lock_id = ? FOR UPDATE",
                Integer.class,
                SESSION_CREATION_LOCK_ID);
    }

    private void insertRefreshToken(UserSession session, String refreshTokenHash) {
        jdbc.update(
                "INSERT INTO user_session_refresh_tokens (token_hash, session_id, consumed, expires_at) VALUES (?, ?, ?, ?)",
                refreshTokenHash,
                session.sessionId(),
                false,
                timestamp(session.expiresAt()));
        jdbc.update(
                "UPDATE user_sessions SET current_refresh_token_hash = ? WHERE session_id = ?",
                refreshTokenHash,
                session.sessionId());
    }

    @Override
    public RotationResult rotate(String presentedHash, String replacementHash, Duration refreshTtl, Instant now) {
        return transactions.execute(status -> {
            List<String> sessionIds = jdbc.query(
                    "SELECT session_id FROM user_session_refresh_tokens WHERE token_hash = ?",
                    (row, index) -> row.getString("session_id"),
                    presentedHash);
            if (sessionIds.isEmpty()) {
                return new RotationResult(RotationStatus.INVALID, null);
            }
            UserSession session = lockSession(sessionIds.getFirst());
            if (session == null) {
                return new RotationResult(RotationStatus.INVALID, null);
            }
            List<RefreshToken> tokens = jdbc.query(
                    "SELECT consumed, expires_at FROM user_session_refresh_tokens WHERE token_hash = ? FOR UPDATE",
                    (row, index) -> new RefreshToken(row.getBoolean("consumed"), instant(row, "expires_at")),
                    presentedHash);
            if (tokens.isEmpty()) {
                return new RotationResult(RotationStatus.INVALID, null);
            }
            RefreshToken presented = tokens.getFirst();
            if (presented.consumed()) {
                UserSession revoked = revokeFamily(session, now);
                return new RotationResult(RotationStatus.REPLAYED, revoked);
            }
            if (session.revokedAt() != null
                    || !presented.expiresAt().isAfter(now)
                    || !session.absoluteExpiresAt().isAfter(now)) {
                return new RotationResult(RotationStatus.INVALID, session);
            }

            Instant replacementExpiry = now.plus(refreshTtl);
            if (replacementExpiry.isAfter(session.absoluteExpiresAt())) {
                replacementExpiry = session.absoluteExpiresAt();
            }
            UserSession rotated = new UserSession(
                    session.sessionId(),
                    session.username(),
                    session.securityVersion(),
                    session.authenticatedAt(),
                    session.authenticationMethods(),
                    session.createdAt(),
                    now,
                    replacementExpiry,
                    session.absoluteExpiresAt(),
                    null,
                    session.clientIp(),
                    session.device());
            jdbc.update(
                    "UPDATE user_session_refresh_tokens SET consumed = ? WHERE token_hash = ?", true, presentedHash);
            jdbc.update(
                    "INSERT INTO user_session_refresh_tokens (token_hash, session_id, consumed, expires_at) VALUES (?, ?, ?, ?)",
                    replacementHash,
                    session.sessionId(),
                    false,
                    timestamp(replacementExpiry));
            jdbc.update(
                    "UPDATE user_sessions SET last_used_at = ?, expires_at = ?, current_refresh_token_hash = ? WHERE session_id = ?",
                    timestamp(now),
                    timestamp(replacementExpiry),
                    replacementHash,
                    session.sessionId());
            return new RotationResult(RotationStatus.ROTATED, rotated);
        });
    }

    @Override
    public boolean revoke(String sessionId, String username, Instant revokedAt) {
        return transactions.execute(status -> {
            List<UserSession> rows = jdbc.query(
                    "SELECT * FROM user_sessions WHERE session_id = ? AND username = ? FOR UPDATE",
                    SESSION_MAPPER,
                    sessionId,
                    username);
            if (rows.isEmpty() || rows.getFirst().revokedAt() != null) {
                return false;
            }
            revokeFamily(rows.getFirst(), revokedAt);
            return true;
        });
    }

    @Override
    public int revokeAll(String username, Instant revokedAt) {
        return transactions.execute(status -> {
            List<UserSession> sessions = jdbc.query(
                    "SELECT * FROM user_sessions WHERE username = ? AND revoked_at IS NULL FOR UPDATE",
                    SESSION_MAPPER,
                    username);
            sessions.forEach(session -> revokeFamily(session, revokedAt));
            return sessions.size();
        });
    }

    @Override
    public List<UserSession> findActiveSessions(String username, Instant now) {
        return jdbc.query(
                "SELECT * FROM user_sessions WHERE username = ? AND revoked_at IS NULL AND expires_at > ? AND absolute_expires_at > ?",
                SESSION_MAPPER,
                username,
                timestamp(now),
                timestamp(now));
    }

    private void insertSession(UserSession session) {
        jdbc.update(
                "INSERT INTO user_sessions (session_id, username, security_version, authenticated_at, authentication_methods, created_at, last_used_at, expires_at, absolute_expires_at, revoked_at, client_ip, device, current_refresh_token_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                session.sessionId(),
                session.username(),
                session.securityVersion(),
                timestamp(session.authenticatedAt()),
                encodeMethods(session.authenticationMethods()),
                timestamp(session.createdAt()),
                timestamp(session.lastUsedAt()),
                timestamp(session.expiresAt()),
                timestamp(session.absoluteExpiresAt()),
                nullableTimestamp(session.revokedAt()),
                session.clientIp(),
                session.device(),
                null);
    }

    private UserSession lockSession(String sessionId) {
        List<UserSession> rows =
                jdbc.query("SELECT * FROM user_sessions WHERE session_id = ? FOR UPDATE", SESSION_MAPPER, sessionId);
        return rows.isEmpty() ? null : rows.getFirst();
    }

    private UserSession revokeFamily(UserSession session, Instant revokedAt) {
        UserSession revoked = new UserSession(
                session.sessionId(),
                session.username(),
                session.securityVersion(),
                session.authenticatedAt(),
                session.authenticationMethods(),
                session.createdAt(),
                session.lastUsedAt(),
                session.expiresAt(),
                session.absoluteExpiresAt(),
                session.revokedAt() == null ? revokedAt : session.revokedAt(),
                session.clientIp(),
                session.device());
        jdbc.update(
                "UPDATE user_sessions SET revoked_at = ?, current_refresh_token_hash = NULL WHERE session_id = ?",
                timestamp(revoked.revokedAt()),
                session.sessionId());
        jdbc.update(
                "UPDATE user_session_refresh_tokens SET consumed = ? WHERE session_id = ?", true, session.sessionId());
        return revoked;
    }

    private static UserSession mapSession(ResultSet row, int index) throws SQLException {
        Timestamp revoked = row.getTimestamp("revoked_at");
        return new UserSession(
                row.getString("session_id"),
                row.getString("username"),
                row.getLong("security_version"),
                instant(row, "authenticated_at"),
                decodeMethods(row.getString("authentication_methods")),
                instant(row, "created_at"),
                instant(row, "last_used_at"),
                instant(row, "expires_at"),
                instant(row, "absolute_expires_at"),
                revoked == null ? null : revoked.toInstant(),
                row.getString("client_ip"),
                row.getString("device"));
    }

    private static String encodeMethods(List<String> methods) {
        return methods.stream()
                .map(method ->
                        Base64.getUrlEncoder().withoutPadding().encodeToString(method.getBytes(StandardCharsets.UTF_8)))
                .collect(java.util.stream.Collectors.joining(","));
    }

    private static List<String> decodeMethods(String encoded) {
        if (encoded.isEmpty()) {
            return List.of();
        }
        return java.util.Arrays.stream(encoded.split(",", -1))
                .map(value -> new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8))
                .toList();
    }

    private static Timestamp timestamp(Instant instant) {
        return Timestamp.from(instant);
    }

    private static Timestamp nullableTimestamp(Instant instant) {
        return instant == null ? null : timestamp(instant);
    }

    private static Instant instant(ResultSet row, String column) throws SQLException {
        return row.getTimestamp(column).toInstant();
    }

    private record RefreshToken(boolean consumed, Instant expiresAt) {}
}

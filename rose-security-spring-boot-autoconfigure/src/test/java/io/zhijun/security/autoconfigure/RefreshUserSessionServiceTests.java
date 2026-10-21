package io.zhijun.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.zhijun.security.core.IssuedAccessToken;
import io.zhijun.security.core.IssuedSessionTokens;
import io.zhijun.security.core.JwtTokenIssuer;
import io.zhijun.security.core.UserSecurityVersionProvider;
import io.zhijun.security.core.UserSessionClientInfo;
import io.zhijun.security.core.UserSessionConcurrencyPolicy;
import io.zhijun.security.core.UserSessionException;
import io.zhijun.security.core.UserSessionStore;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

class RefreshUserSessionServiceTests {

    private static final Instant NOW = Instant.parse("2026-10-21T12:00:00Z");
    private static final String USERNAME = "person@example.test";
    private static final UserSessionClientInfo CLIENT_INFO = new UserSessionClientInfo("192.0.2.10", "测试设备");

    @Test
    void persistsOnlyHashAndRotatesRefreshToken() {
        Fixture fixture = new Fixture();
        IssuedSessionTokens created =
                fixture.service.create(fixture.user, List.of("pwd"), NOW.minusSeconds(2), CLIENT_INFO);

        assertThat(created.refreshToken()).hasSize(43);
        assertThat(fixture.store.tokens).hasSize(1);
        assertThat(fixture.store.tokens).doesNotContainKey(created.refreshToken());
        assertThat(fixture.store.tokens.keySet().iterator().next()).hasSize(43);

        IssuedSessionTokens refreshed = fixture.service.refresh(created.refreshToken());

        assertThat(refreshed.refreshToken()).isNotEqualTo(created.refreshToken());
        assertThat(refreshed.sessionId()).isEqualTo(created.sessionId());
        assertThat(fixture.store.tokens).hasSize(2);
        assertThat(fixture.store.hasConsumedAndActiveTokens()).isTrue();
    }

    @Test
    void replayingConsumedTokenRevokesTheWholeFamily() {
        Fixture fixture = new Fixture();
        IssuedSessionTokens created =
                fixture.service.create(fixture.user, List.of("pwd"), NOW.minusSeconds(2), CLIENT_INFO);
        fixture.service.refresh(created.refreshToken());

        assertThatThrownBy(() -> fixture.service.refresh(created.refreshToken()))
                .isInstanceOfSatisfying(
                        UserSessionException.class,
                        exception -> assertThat(exception.reason())
                                .isEqualTo(UserSessionException.Reason.REFRESH_TOKEN_REPLAYED));
        assertThat(fixture.store.session.revokedAt()).isEqualTo(NOW);
        assertThat(fixture.store.allTokensConsumed()).isTrue();
    }

    @Test
    void securityVersionChangeInvalidatesAndRevokesSession() {
        Fixture fixture = new Fixture();
        IssuedSessionTokens created =
                fixture.service.create(fixture.user, List.of("pwd"), NOW.minusSeconds(2), CLIENT_INFO);
        fixture.securityVersion.set(8);

        assertThatThrownBy(() -> fixture.service.refresh(created.refreshToken()))
                .isInstanceOfSatisfying(
                        UserSessionException.class,
                        exception -> assertThat(exception.reason())
                                .isEqualTo(UserSessionException.Reason.SESSION_INVALIDATED));
        assertThat(fixture.store.session.revokedAt()).isEqualTo(NOW);
        assertThat(fixture.store.allTokensConsumed()).isTrue();
    }

    @Test
    void usernameChangeInvalidatesAndRevokesSession() {
        Fixture fixture = new Fixture();
        IssuedSessionTokens created =
                fixture.service.create(fixture.user, List.of("pwd"), NOW.minusSeconds(2), CLIENT_INFO);
        fixture.currentUser = User.withUsername("renamed@example.test")
                .password("unused")
                .authorities("ROLE_USER")
                .build();

        assertThatThrownBy(() -> fixture.service.refresh(created.refreshToken()))
                .isInstanceOfSatisfying(
                        UserSessionException.class,
                        exception -> assertThat(exception.reason())
                                .isEqualTo(UserSessionException.Reason.SESSION_INVALIDATED));
        assertThat(fixture.store.session.revokedAt()).isEqualTo(NOW);
        assertThat(fixture.store.allTokensConsumed()).isTrue();
    }

    @Test
    void configuredSessionLimitRejectsNewLogin() {
        Fixture fixture = new Fixture();
        fixture.sessionPolicy =
                new UserSessionConcurrencyPolicy.Policy(1, UserSessionConcurrencyPolicy.LimitBehavior.DENY_NEW);
        fixture.service.create(fixture.user, List.of("pwd"), NOW.minusSeconds(2), CLIENT_INFO);

        assertThatThrownBy(() -> fixture.service.create(fixture.user, List.of("pwd"), NOW.minusSeconds(1), CLIENT_INFO))
                .isInstanceOfSatisfying(
                        UserSessionException.class,
                        exception -> assertThat(exception.reason())
                                .isEqualTo(UserSessionException.Reason.SESSION_LIMIT_REACHED));
    }

    private static final class Fixture {

        private final UserDetails user = User.withUsername(USERNAME)
                .password("unused")
                .authorities("ROLE_USER")
                .build();
        private UserDetails currentUser = user;
        private final MemoryUserSessionStore store = new MemoryUserSessionStore();
        private final AtomicLong securityVersion = new AtomicLong(7);
        private UserSessionConcurrencyPolicy.Policy sessionPolicy = UserSessionConcurrencyPolicy.Policy.unlimited();
        private final RefreshUserSessionService service;

        private Fixture() {
            JwtTokenIssuer issuer = (principal, sessionId, methods, authenticatedAt, version) ->
                    new IssuedAccessToken("access-" + sessionId, NOW, NOW.plusSeconds(600));
            UserDetailsService userDetailsService =
                    username -> USERNAME.equals(username) ? currentUser : throwUsernameNotFound(username);
            UserSecurityVersionProvider versionProvider = username -> securityVersion.get();
            AuthSecurityProperties properties = new AuthSecurityProperties(
                    true,
                    new AuthSecurityProperties.Jwt(
                            true,
                            Duration.ofMinutes(10),
                            Duration.ofDays(14),
                            Duration.ofDays(30),
                            "https://issuer.example.test",
                            "api",
                            null,
                            null,
                            null),
                    null);
            service = new RefreshUserSessionService(
                    issuer,
                    store,
                    userDetailsService,
                    versionProvider,
                    username -> sessionPolicy,
                    properties,
                    Clock.fixed(NOW, ZoneOffset.UTC),
                    new java.security.SecureRandom());
        }

        private static UserDetails throwUsernameNotFound(String username) {
            throw new org.springframework.security.core.userdetails.UsernameNotFoundException(username);
        }
    }

    private static final class MemoryUserSessionStore implements UserSessionStore {

        private final Map<String, StoredRefreshToken> tokens = new HashMap<>();
        private UserSession session;

        @Override
        public synchronized void create(UserSession newSession) {
            session = newSession;
        }

        @Override
        public synchronized void create(UserSession newSession, String refreshTokenHash) {
            session = newSession;
            tokens.put(refreshTokenHash, new StoredRefreshToken(false, session.expiresAt()));
        }

        @Override
        public synchronized SessionCreationResult create(
                UserSession newSession,
                String refreshTokenHash,
                UserSessionConcurrencyPolicy.Policy concurrencyPolicy) {
            if (concurrencyPolicy.maximumActiveSessions() > 0
                    && session != null
                    && session.username().equals(newSession.username())
                    && session.revokedAt() == null
                    && session.expiresAt().isAfter(newSession.createdAt())) {
                if (concurrencyPolicy.limitBehavior() == UserSessionConcurrencyPolicy.LimitBehavior.DENY_NEW) {
                    return SessionCreationResult.LIMIT_REACHED;
                }
                session = revokedAt(newSession.createdAt());
                tokens.replaceAll((hash, value) -> new StoredRefreshToken(true, value.expiresAt()));
            }
            create(newSession, refreshTokenHash);
            return SessionCreationResult.CREATED;
        }

        @Override
        public synchronized RotationResult rotate(
                String presentedTokenHash, String replacementTokenHash, Duration refreshTtl, Instant now) {
            StoredRefreshToken token = tokens.get(presentedTokenHash);
            if (token == null) {
                return new RotationResult(RotationStatus.INVALID, null);
            }
            if (token.consumed()) {
                session = revokedAt(now);
                tokens.replaceAll((hash, value) -> new StoredRefreshToken(true, value.expiresAt()));
                return new RotationResult(RotationStatus.REPLAYED, session);
            }
            if (session.revokedAt() != null
                    || !token.expiresAt().isAfter(now)
                    || !session.absoluteExpiresAt().isAfter(now)) {
                return new RotationResult(RotationStatus.INVALID, session);
            }
            Instant replacementExpiresAt = now.plus(refreshTtl);
            if (replacementExpiresAt.isAfter(session.absoluteExpiresAt())) {
                replacementExpiresAt = session.absoluteExpiresAt();
            }
            session = new UserSession(
                    session.sessionId(),
                    session.username(),
                    session.securityVersion(),
                    session.authenticatedAt(),
                    session.authenticationMethods(),
                    session.createdAt(),
                    now,
                    replacementExpiresAt,
                    session.absoluteExpiresAt(),
                    session.revokedAt(),
                    session.clientIp(),
                    session.device());
            tokens.put(presentedTokenHash, new StoredRefreshToken(true, token.expiresAt()));
            tokens.put(replacementTokenHash, new StoredRefreshToken(false, replacementExpiresAt));
            return new RotationResult(RotationStatus.ROTATED, session);
        }

        @Override
        public synchronized boolean revoke(String sessionId, String username, Instant revokedAt) {
            if (session == null
                    || !session.sessionId().equals(sessionId)
                    || !session.username().equals(username)) {
                return false;
            }
            session = revokedAt(revokedAt);
            tokens.replaceAll((hash, value) -> new StoredRefreshToken(true, value.expiresAt()));
            return true;
        }

        @Override
        public synchronized int revokeAll(String username, Instant revokedAt) {
            return revoke(session.sessionId(), username, revokedAt) ? 1 : 0;
        }

        @Override
        public synchronized List<UserSession> findActiveSessions(String username, Instant now) {
            return session != null && session.username().equals(username) && session.revokedAt() == null
                    ? List.of(session)
                    : List.of();
        }

        private UserSession revokedAt(Instant when) {
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
                    when,
                    session.clientIp(),
                    session.device());
        }

        private boolean allTokensConsumed() {
            return !tokens.isEmpty() && tokens.values().stream().allMatch(StoredRefreshToken::consumed);
        }

        private boolean hasConsumedAndActiveTokens() {
            return tokens.values().stream().anyMatch(StoredRefreshToken::consumed)
                    && tokens.values().stream().anyMatch(token -> !token.consumed());
        }

        private record StoredRefreshToken(boolean consumed, Instant expiresAt) {}
    }
}

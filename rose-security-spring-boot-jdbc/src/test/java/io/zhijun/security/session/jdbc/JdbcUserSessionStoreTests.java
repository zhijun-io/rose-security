package io.zhijun.security.session.jdbc;

import static org.assertj.core.api.Assertions.assertThat;

import io.zhijun.security.core.UserSessionConcurrencyPolicy;
import io.zhijun.security.core.UserSessionStore;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;

class JdbcUserSessionStoreTests {

    private static final Instant NOW = Instant.parse("2026-10-21T00:00:00Z");

    private JdbcTemplate jdbc;
    private JdbcUserSessionStore store;

    @BeforeEach
    void setUp() {
        JdbcDataSource dataSource = new JdbcDataSource();
        dataSource.setURL("jdbc:h2:mem:" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1");
        jdbc = new JdbcTemplate(dataSource);
        new ResourceDatabasePopulator(new ClassPathResource("db/rose-security-session-store-schema.sql"))
                .execute(dataSource);
        store = new JdbcUserSessionStore(jdbc, new DataSourceTransactionManager(dataSource));
    }

    @Test
    void rotatesOnceAndRevokesFamilyWhenConsumedTokenIsReplayed() {
        UserSessionStore.UserSession session = session("session-1", "user@example.test");
        store.create(session, "hash-1");

        UserSessionStore.RotationResult rotated =
                store.rotate("hash-1", "hash-2", Duration.ofDays(14), NOW.plusSeconds(60));

        assertThat(rotated.status()).isEqualTo(UserSessionStore.RotationStatus.ROTATED);
        assertThat(rotated.session().expiresAt()).isEqualTo(NOW.plusSeconds(60).plus(Duration.ofDays(14)));
        assertThat(store.findActiveSessions(session.username(), NOW.plusSeconds(60)))
                .hasSize(1);

        UserSessionStore.RotationResult replayed =
                store.rotate("hash-1", "hash-3", Duration.ofDays(14), NOW.plusSeconds(120));

        assertThat(replayed.status()).isEqualTo(UserSessionStore.RotationStatus.REPLAYED);
        assertThat(store.findActiveSessions(session.username(), NOW.plusSeconds(120)))
                .isEmpty();
        assertThat(jdbc.queryForObject(
                        "SELECT COUNT(*) FROM user_session_refresh_tokens WHERE token_hash = ? AND consumed = TRUE",
                        Integer.class,
                        "hash-2"))
                .isEqualTo(1);
    }

    @Test
    void persistsSessionsWithoutRefreshTokensAndSupportsSingleAndAllRevocation() {
        UserSessionStore.UserSession first = session("session-1", "user@example.test");
        UserSessionStore.UserSession second = session("session-2", "user@example.test");
        store.create(first);
        store.create(second);

        assertThat(store.revoke(first.sessionId(), first.username(), NOW.plusSeconds(1)))
                .isTrue();
        assertThat(store.findActiveSessions(first.username(), NOW.plusSeconds(1)))
                .extracting(UserSessionStore.UserSession::sessionId)
                .containsExactly(second.sessionId());
        assertThat(store.revokeAll(first.username(), NOW.plusSeconds(2))).isEqualTo(1);
        assertThat(store.findActiveSessions(first.username(), NOW.plusSeconds(2)))
                .isEmpty();
    }

    @Test
    void acceptsNullRefreshHashWhenRefreshIsDisabled() {
        UserSessionStore.UserSession session = session("session-no-refresh", "user@example.test");

        store.create(session, null);

        assertThat(store.findActiveSessions(session.username(), NOW)).containsExactly(session);
        assertThat(jdbc.queryForObject(
                        "SELECT COUNT(*) FROM user_session_refresh_tokens WHERE session_id = ?",
                        Integer.class,
                        session.sessionId()))
                .isZero();
    }

    @Test
    void rejectsSessionWhenConfiguredLimitIsReached() {
        store.create(session("session-1", "user@example.test"));

        UserSessionStore.SessionCreationResult result = store.create(
                session("session-2", "user@example.test"),
                null,
                new UserSessionConcurrencyPolicy.Policy(1, UserSessionConcurrencyPolicy.LimitBehavior.DENY_NEW));

        assertThat(result).isEqualTo(UserSessionStore.SessionCreationResult.LIMIT_REACHED);
        assertThat(store.findActiveSessions("user@example.test", NOW)).hasSize(1);
    }

    @Test
    void revokesOldestSessionWhenConfiguredLimitIsReached() {
        store.create(session("session-1", "user@example.test"));
        store.create(session("session-2", "user@example.test"));

        UserSessionStore.SessionCreationResult result = store.create(
                session("session-3", "user@example.test"),
                null,
                new UserSessionConcurrencyPolicy.Policy(2, UserSessionConcurrencyPolicy.LimitBehavior.REVOKE_OLDEST));

        assertThat(result).isEqualTo(UserSessionStore.SessionCreationResult.CREATED);
        assertThat(store.findActiveSessions("user@example.test", NOW))
                .extracting(UserSessionStore.UserSession::sessionId)
                .containsExactly("session-2", "session-3");
    }

    @Test
    void concurrentFirstSessionsRespectTheLimit() throws Exception {
        var policy = new UserSessionConcurrencyPolicy.Policy(1, UserSessionConcurrencyPolicy.LimitBehavior.DENY_NEW);
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var first = executor.submit(() -> createAfterBarrier("session-1", policy, ready, start));
            var second = executor.submit(() -> createAfterBarrier("session-2", policy, ready, start));
            ready.await();
            start.countDown();

            assertThat(List.of(first.get(), second.get()))
                    .containsExactlyInAnyOrder(
                            UserSessionStore.SessionCreationResult.CREATED,
                            UserSessionStore.SessionCreationResult.LIMIT_REACHED);
            assertThat(store.findActiveSessions("user@example.test", NOW)).hasSize(1);
        }
    }

    private UserSessionStore.SessionCreationResult createAfterBarrier(
            String sessionId, UserSessionConcurrencyPolicy.Policy policy, CountDownLatch ready, CountDownLatch start)
            throws InterruptedException {
        ready.countDown();
        start.await();
        return store.create(session(sessionId, "user@example.test"), null, policy);
    }

    private static UserSessionStore.UserSession session(String sessionId, String username) {
        return new UserSessionStore.UserSession(
                sessionId,
                username,
                3,
                NOW,
                List.of("pwd", "webauthn"),
                NOW,
                NOW,
                NOW.plus(Duration.ofDays(14)),
                NOW.plus(Duration.ofDays(30)),
                null,
                "127.0.0.1",
                "Browser · OS");
    }
}

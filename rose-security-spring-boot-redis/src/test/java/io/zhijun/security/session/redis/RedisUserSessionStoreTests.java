package io.zhijun.security.session.redis;

import static org.assertj.core.api.Assertions.assertThat;

import io.zhijun.security.core.UserSessionConcurrencyPolicy;
import io.zhijun.security.core.UserSessionStore;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;

class RedisUserSessionStoreTests {

    private static final Instant NOW = Instant.parse("2026-10-21T00:00:00Z");
    private static GenericContainer<?> redisContainer;
    private static LettuceConnectionFactory connectionFactory;
    private static StringRedisTemplate redis;
    private RedisUserSessionStore store;

    @BeforeAll
    static void startRedis() {
        org.junit.jupiter.api.Assumptions.assumeTrue(
                DockerClientFactory.instance().isDockerAvailable());
        redisContainer = new GenericContainer<>(DockerImageName.parse("redis:7.4-alpine")).withExposedPorts(6379);
        redisContainer.start();
        RedisStandaloneConfiguration config =
                new RedisStandaloneConfiguration(redisContainer.getHost(), redisContainer.getFirstMappedPort());
        connectionFactory = new LettuceConnectionFactory(config);
        connectionFactory.afterPropertiesSet();
        redis = new StringRedisTemplate(connectionFactory);
        redis.afterPropertiesSet();
    }

    @AfterAll
    static void stopRedis() {
        if (connectionFactory != null) {
            connectionFactory.destroy();
        }
        if (redisContainer != null) {
            redisContainer.stop();
        }
    }

    @BeforeEach
    void setUp() {
        if (redis != null) {
            redis.getConnectionFactory().getConnection().serverCommands().flushDb();
            store = new RedisUserSessionStore(redis);
        }
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
    }

    @Test
    void revokesAllActiveSessionsForAUser() {
        store.create(session("session-1", "user@example.test"));
        store.create(session("session-2", "user@example.test"), "hash-2");

        assertThat(store.revokeAll("user@example.test", NOW.plusSeconds(1))).isEqualTo(2);
        assertThat(store.findActiveSessions("user@example.test", NOW.plusSeconds(1)))
                .isEmpty();
        assertThat(store.rotate("hash-2", "hash-3", Duration.ofDays(14), NOW.plusSeconds(2))
                        .status())
                .isEqualTo(UserSessionStore.RotationStatus.REPLAYED);
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
        store.create(session("session-1", "user@example.test"), "hash-1");
        store.create(session("session-2", "user@example.test"), "hash-2");

        UserSessionStore.SessionCreationResult result = store.create(
                session("session-3", "user@example.test"),
                "hash-3",
                new UserSessionConcurrencyPolicy.Policy(2, UserSessionConcurrencyPolicy.LimitBehavior.REVOKE_OLDEST));

        assertThat(result).isEqualTo(UserSessionStore.SessionCreationResult.CREATED);
        assertThat(store.findActiveSessions("user@example.test", NOW))
                .extracting(UserSessionStore.UserSession::sessionId)
                .containsExactly("session-2", "session-3");
        assertThat(store.rotate("hash-1", "hash-4", Duration.ofDays(14), NOW.plusSeconds(1))
                        .status())
                .isEqualTo(UserSessionStore.RotationStatus.REPLAYED);
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

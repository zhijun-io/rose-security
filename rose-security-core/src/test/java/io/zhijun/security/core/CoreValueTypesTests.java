package io.zhijun.security.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class CoreValueTypesTests {

    private static final Instant NOW = Instant.parse("2026-10-26T00:00:00Z");

    @Test
    void tokenValuesValidateLifetimesAndRedactSecrets() {
        var access = new IssuedAccessToken("access-secret", NOW, NOW.plusSeconds(10));
        var tokens = new IssuedSessionTokens(
                "access-secret", NOW.plusSeconds(10), "refresh-secret", NOW.plusSeconds(20), "session-1");

        assertThat(access.toString()).doesNotContain("access-secret");
        assertThat(tokens.toString()).doesNotContain("access-secret", "refresh-secret");
        assertThatThrownBy(() -> new IssuedAccessToken("access", NOW, NOW))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new IssuedSessionTokens("access", NOW, "refresh", null, "session"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void sessionContractsCopyMutableAuthenticationStateAndRejectUnsafeLimits() {
        var methods = new java.util.ArrayList<>(List.of("pwd"));
        var details = new UserSessionAuthenticationDetails(Set.copyOf(methods), NOW, null);
        methods.add("totp");
        assertThat(details.authenticationMethods()).containsExactly("pwd");
        assertThat(UserSessionConcurrencyPolicy.Policy.unlimited().maximumActiveSessions())
                .isZero();
        assertThatThrownBy(() -> new UserSessionConcurrencyPolicy.Policy(
                        -1, UserSessionConcurrencyPolicy.LimitBehavior.DENY_NEW))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new UserSessionConcurrencyPolicy.Policy(1, null))
                .isInstanceOf(IllegalArgumentException.class);

        var session = new UserSessionStore.UserSession(
                "session",
                "user",
                1,
                NOW,
                methods,
                NOW,
                NOW,
                NOW.plusSeconds(30),
                NOW.plusSeconds(60),
                null,
                null,
                null);
        assertThat(session.authenticationMethods()).containsExactly("pwd", "totp");
        assertThat(new UserSessionView("session", NOW, NOW, NOW.plusSeconds(30), NOW.plusSeconds(60), null, null)
                        .sessionId())
                .isEqualTo("session");
    }

    @Test
    void sessionStoreDefaultCreateSupportsUnlimitedPolicyOnly() {
        TestStore store = new TestStore();
        var session = new UserSessionStore.UserSession(
                "session",
                "user",
                1,
                NOW,
                List.of("pwd"),
                NOW,
                NOW,
                NOW.plusSeconds(30),
                NOW.plusSeconds(60),
                null,
                null,
                null);

        assertThat(store.create(session, null, UserSessionConcurrencyPolicy.Policy.unlimited()))
                .isEqualTo(UserSessionStore.SessionCreationResult.CREATED);
        assertThat(store.createdWithoutRefreshToken).isSameAs(session);
        assertThatThrownBy(() -> store.create(
                        session,
                        "hash",
                        new UserSessionConcurrencyPolicy.Policy(
                                1, UserSessionConcurrencyPolicy.LimitBehavior.DENY_NEW)))
                .isInstanceOf(IllegalStateException.class);
    }

    private static final class TestStore implements UserSessionStore {

        private UserSession createdWithoutRefreshToken;

        @Override
        public void create(UserSession session) {
            createdWithoutRefreshToken = session;
        }

        @Override
        public void create(UserSession session, String refreshTokenHash) {}

        @Override
        public RotationResult rotate(
                String presentedHash, String replacementHash, java.time.Duration ttl, Instant now) {
            return new RotationResult(RotationStatus.INVALID, null);
        }

        @Override
        public boolean revoke(String sessionId, String username, Instant revokedAt) {
            return false;
        }

        @Override
        public int revokeAll(String username, Instant revokedAt) {
            return 0;
        }

        @Override
        public List<UserSession> findActiveSessions(String username, Instant now) {
            return List.of();
        }
    }
}

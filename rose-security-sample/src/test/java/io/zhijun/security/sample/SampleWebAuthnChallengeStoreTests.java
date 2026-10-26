package io.zhijun.security.sample;

import static org.assertj.core.api.Assertions.assertThat;

import io.zhijun.security.core.WebAuthnMfaChallenge;
import java.time.Instant;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

class SampleWebAuthnChallengeStoreTests {

    private final SampleMfaStore store = new SampleMfaStore();
    private final Instant now = Instant.parse("2026-10-22T00:00:00Z");
    private final WebAuthnMfaChallenge challenge = new WebAuthnMfaChallenge(
            "user@example.test", "login", "login-transaction-hash", new byte[] {1, 2, 3}, now.plusSeconds(60));

    @Test
    void challengeMustMatchItsUserOperationAndLoginTransactionAndCanOnlyBeConsumedOnce() {
        store.save("challenge-hash", challenge);

        assertThat(store.consume("challenge-hash", "other@example.test", "login", "login-transaction-hash", now))
                .isEmpty();
        assertThat(store.consume("challenge-hash", "user@example.test", "registration", "login-transaction-hash", now))
                .isEmpty();
        assertThat(store.consume("challenge-hash", "user@example.test", "login", "other-transaction-hash", now))
                .isEmpty();
        assertThat(store.consume("challenge-hash", "user@example.test", "login", "login-transaction-hash", now))
                .contains(challenge);
        assertThat(store.consume("challenge-hash", "user@example.test", "login", "login-transaction-hash", now))
                .isEmpty();
    }

    @Test
    void expiredChallengeIsConsumedAndRejected() {
        store.save("challenge-hash", challenge);

        assertThat(store.consume(
                        "challenge-hash", "user@example.test", "login", "login-transaction-hash", now.plusSeconds(60)))
                .isEmpty();
        assertThat(store.consume("challenge-hash", "user@example.test", "login", "login-transaction-hash", now))
                .isEmpty();
    }

    @Test
    void concurrentConsumptionSucceedsOnlyOnce() {
        store.save("challenge-hash", challenge);

        long successfulConsumers = IntStream.range(0, 32)
                .parallel()
                .filter(index -> store.consume(
                                "challenge-hash", "user@example.test", "login", "login-transaction-hash", now)
                        .isPresent())
                .count();

        assertThat(successfulConsumers).isEqualTo(1);
    }
}

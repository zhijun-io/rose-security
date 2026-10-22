package io.zhijun.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import io.zhijun.security.core.EmailMfaStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class EmailMfaServiceTests {

    private static final Instant NOW = Instant.parse("2026-10-21T12:00:00Z");
    private static final String USERNAME = "user@example.test";

    @Test
    void loginCodeIsBoundToUserAndTransactionAndConsumedOnce() {
        InMemoryEmailMfaStore store = new InMemoryEmailMfaStore();
        CapturingSender sender = new CapturingSender();
        EmailMfaService service = new EmailMfaService(store, sender, new SecureRandom());

        service.beginLogin(USERNAME, "opaque-transaction-token", NOW.plusSeconds(300));

        assertThat(sender.email).isEqualTo(USERNAME);
        assertThat(sender.code).matches("[0-9]{6}");
        assertThat(store.challenges.values())
                .allSatisfy(challenge -> assertThat(challenge.proofHash()).isNotEqualTo(sender.code));
        assertThat(service.verifyLogin("another@example.test", "opaque-transaction-token", sender.code, NOW))
                .isFalse();
        assertThat(service.verifyLogin(USERNAME, "another-transaction-token", sender.code, NOW))
                .isFalse();
        assertThat(service.verifyLogin(USERNAME, "opaque-transaction-token", "bad-code", NOW))
                .isFalse();
        assertThat(service.verifyLogin(USERNAME, "opaque-transaction-token", sender.code, NOW))
                .isTrue();
        assertThat(service.verifyLogin(USERNAME, "opaque-transaction-token", sender.code, NOW))
                .isFalse();
    }

    @Test
    void emailMfaIsEnabledOnlyAfterTheUserConfirmsAnEnrollmentCode() {
        InMemoryEmailMfaStore store = new InMemoryEmailMfaStore();
        CapturingSender sender = new CapturingSender();
        EmailMfaService service = new EmailMfaService(store, sender, new SecureRandom());

        EmailMfaService.Challenge challenge = service.beginEnrollment(USERNAME, Duration.ofMinutes(5), NOW);

        assertThat(service.isEnabled(USERNAME)).isFalse();
        assertThat(service.confirmEnrollment(USERNAME, null, sender.code, NOW, 5))
                .isFalse();
        assertThat(service.confirmEnrollment(USERNAME, challenge.token(), "00000x", NOW, 5))
                .isFalse();
        assertThat(service.confirmEnrollment(USERNAME, challenge.token(), sender.code, NOW, 5))
                .isTrue();
        assertThat(service.isEnabled(USERNAME)).isTrue();
        EmailMfaService.Challenge removal = service.beginRemoval(USERNAME, Duration.ofMinutes(5), NOW);
        assertThat(service.isEnabled(USERNAME)).isTrue();
        assertThat(service.confirmRemoval(USERNAME, removal.token(), sender.code, NOW, 5))
                .isTrue();
        assertThat(service.isEnabled(USERNAME)).isFalse();
    }

    private static final class CapturingSender implements io.zhijun.security.core.MfaEmailSender {

        private String email;
        private String code;

        @Override
        public void send(String email, String code, Instant expiresAt) {
            this.email = email;
            this.code = code;
        }
    }

    private static final class InMemoryEmailMfaStore implements EmailMfaStore {

        private final Map<ChallengeKey, Challenge> challenges = new HashMap<>();
        private final Set<String> enabled = new HashSet<>();

        @Override
        public synchronized void saveChallenge(
                String username, String challengeId, String purpose, String proofHash, Instant expiresAt) {
            challenges.put(new ChallengeKey(username, challengeId, purpose), new Challenge(proofHash, expiresAt, 0));
        }

        @Override
        public synchronized boolean consumeChallenge(
                String username, String challengeId, String purpose, String expectedProofHash, Instant now) {
            ChallengeKey key = new ChallengeKey(username, challengeId, purpose);
            Challenge challenge = challenges.get(key);
            if (challenge == null || !challenge.expiresAt().isAfter(now)) {
                challenges.remove(key);
                return false;
            }
            boolean matches = MessageDigest.isEqual(
                    challenge.proofHash().getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                    expectedProofHash.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            if (matches) challenges.remove(key);
            return matches;
        }

        @Override
        public synchronized boolean consumeChallengeAndSetEnabled(
                String username,
                String challengeId,
                String purpose,
                String expectedProofHash,
                Instant now,
                boolean enabledAfterConsume) {
            boolean consumed = consumeChallenge(username, challengeId, purpose, expectedProofHash, now);
            if (consumed) setEnabled(username, enabledAfterConsume);
            return consumed;
        }

        @Override
        public synchronized boolean recordFailedAttempt(
                String username, String challengeId, String purpose, Instant now, int maximumAttempts) {
            ChallengeKey key = new ChallengeKey(username, challengeId, purpose);
            Challenge challenge = challenges.get(key);
            if (challenge == null || !challenge.expiresAt().isAfter(now)) {
                challenges.remove(key);
                return false;
            }
            int failures = challenge.failures() + 1;
            if (failures >= maximumAttempts) challenges.remove(key);
            else challenges.put(key, new Challenge(challenge.proofHash(), challenge.expiresAt(), failures));
            return failures < maximumAttempts;
        }

        @Override
        public synchronized boolean isEnabled(String username) {
            return enabled.contains(username);
        }

        private synchronized void setEnabled(String username, boolean value) {
            if (value) enabled.add(username);
            else enabled.remove(username);
        }

        private record ChallengeKey(String username, String id, String purpose) {}

        private record Challenge(String proofHash, Instant expiresAt, int failures) {}
    }
}

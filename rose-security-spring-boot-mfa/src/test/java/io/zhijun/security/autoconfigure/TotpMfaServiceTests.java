package io.zhijun.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import io.zhijun.security.core.MfaFactorAuthenticationToken;
import io.zhijun.security.core.TotpCredential;
import io.zhijun.security.core.TotpCredentialStore;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base32;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;

class TotpMfaServiceTests {

    private static final Instant NOW = Instant.parse("2026-10-21T12:00:00Z");

    @Test
    void enrollmentRequiresConfirmationAndAcceptedTimeStepsCannotBeReplayed() throws Exception {
        MutableClock clock = new MutableClock(NOW);
        InMemoryTotpCredentialStore store = new InMemoryTotpCredentialStore();
        TotpMfaService service =
                new TotpMfaService(store, new java.security.SecureRandom(), clock, Duration.ofMinutes(5), 5);

        TotpMfaService.Enrollment enrollment = service.beginEnrollment("user@example.test", "Example App");

        assertThat(enrollment.secret()).matches("[A-Z2-7]{32}");
        assertThat(enrollment.otpauthUri())
                .contains("otpauth://totp/", "secret=" + enrollment.secret(), "issuer=Example%20App");
        assertThat(enrollment.toString()).doesNotContain(enrollment.secret(), enrollment.otpauthUri());
        assertThat(store.active).doesNotContainKey("user@example.test");
        assertThat(service.confirmEnrollment("user@example.test", "not-a-code")).isFalse();

        String code = codeFor(enrollment.secret(), NOW);
        assertThat(service.confirmEnrollment("user@example.test", code)).isTrue();
        assertThat(service.verify("user@example.test", code)).isFalse();

        clock.set(NOW.plusSeconds(30));
        String nextCode = codeFor(enrollment.secret(), clock.instant());
        assertThat(service.verify("user@example.test", nextCode)).isTrue();
        assertThat(service.verify("user@example.test", nextCode)).isFalse();
    }

    @Test
    void totpAuthenticationProviderUsesUserDetailsServiceAndRejectsWrongMethod() throws Exception {
        MutableClock clock = new MutableClock(NOW);
        InMemoryTotpCredentialStore store = new InMemoryTotpCredentialStore();
        TotpMfaService service =
                new TotpMfaService(store, new java.security.SecureRandom(), clock, Duration.ofMinutes(5), 5);
        TotpMfaService.Enrollment enrollment = service.beginEnrollment("user@example.test", "Example App");
        assertThat(service.confirmEnrollment("user@example.test", codeFor(enrollment.secret(), NOW)))
                .isTrue();
        clock.set(NOW.plusSeconds(30));
        TotpAuthenticationProvider provider = new TotpAuthenticationProvider(
                service,
                username -> User.withUsername(username)
                        .password("unused")
                        .authorities("ROLE_USER")
                        .build());

        Authentication authenticated = provider.authenticate(MfaFactorAuthenticationToken.unauthenticated(
                "user@example.test", "totp", codeFor(enrollment.secret(), clock.instant())));

        assertThat(authenticated.isAuthenticated()).isTrue();
        assertThat(authenticated.getName()).isEqualTo("user@example.test");
        assertThat(provider.authenticate(
                        MfaFactorAuthenticationToken.unauthenticated("user@example.test", "email", "123456")))
                .isNull();
    }

    @Test
    void invalidEnrollmentProofsInvalidatePendingSecretAtConfiguredLimit() throws Exception {
        MutableClock clock = new MutableClock(NOW);
        InMemoryTotpCredentialStore store = new InMemoryTotpCredentialStore();
        TotpMfaService service =
                new TotpMfaService(store, new java.security.SecureRandom(), clock, Duration.ofMinutes(5), 2);
        TotpMfaService.Enrollment enrollment = service.beginEnrollment("user@example.test", "Example App");

        assertThat(service.confirmEnrollment("user@example.test", "00000x")).isFalse();
        assertThat(service.confirmEnrollment("user@example.test", "00000x")).isFalse();
        assertThat(service.confirmEnrollment("user@example.test", codeFor(enrollment.secret(), NOW)))
                .isFalse();
        assertThat(store.active).doesNotContainKey("user@example.test");
    }

    @Test
    void generatorMatchesRfc6238Sha1Vector() throws Exception {
        byte[] key = "12345678901234567890".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        TimeBasedOneTimePasswordGenerator generator =
                new TimeBasedOneTimePasswordGenerator(Duration.ofSeconds(30), 8, "HmacSHA1");

        assertThat(generator.generateOneTimePasswordString(
                        new SecretKeySpec(key, "HmacSHA1"), Instant.ofEpochSecond(59), java.util.Locale.ROOT))
                .isEqualTo("94287082");
    }

    private static String codeFor(String base32Secret, Instant instant) throws Exception {
        byte[] secret = new Base32().decode(base32Secret);
        return new TimeBasedOneTimePasswordGenerator()
                .generateOneTimePasswordString(new SecretKeySpec(secret, "HmacSHA1"), instant, java.util.Locale.ROOT);
    }

    private static final class MutableClock extends Clock {

        private final AtomicReference<Instant> instant;

        private MutableClock(Instant instant) {
            this.instant = new AtomicReference<>(instant);
        }

        private void set(Instant value) {
            instant.set(value);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant.get();
        }
    }

    private static final class InMemoryTotpCredentialStore implements TotpCredentialStore {

        private final Map<String, Pending> pending = new HashMap<>();
        private final Map<String, Integer> pendingFailures = new HashMap<>();
        private final Map<String, TotpCredential> active = new HashMap<>();

        @Override
        public synchronized void savePending(String username, String base32Secret, Instant expiresAt) {
            pending.put(username, new Pending(base32Secret, expiresAt));
        }

        @Override
        public synchronized Optional<String> findPendingSecret(String username, Instant now) {
            Pending value = pending.get(username);
            return value != null && value.expiresAt().isAfter(now) ? Optional.of(value.secret()) : Optional.empty();
        }

        @Override
        public synchronized boolean recordPendingConfirmationFailure(
                String username, int maximumAttempts, Instant now) {
            Pending value = pending.get(username);
            if (value == null || !value.expiresAt().isAfter(now)) {
                return false;
            }
            int attempts = pendingFailures.merge(username, 1, Integer::sum);
            if (attempts >= maximumAttempts) {
                pending.remove(username);
                pendingFailures.remove(username);
                return false;
            }
            return true;
        }

        @Override
        public synchronized boolean activatePending(
                String username, String expectedBase32Secret, long acceptedTimeStep, Instant now) {
            Pending value = pending.get(username);
            if (value == null
                    || !value.expiresAt().isAfter(now)
                    || !value.secret().equals(expectedBase32Secret)) {
                return false;
            }
            active.put(username, new TotpCredential(expectedBase32Secret, acceptedTimeStep));
            pending.remove(username);
            pendingFailures.remove(username);
            return true;
        }

        @Override
        public synchronized Optional<TotpCredential> findActive(String username) {
            return Optional.ofNullable(active.get(username));
        }

        @Override
        public synchronized boolean consumeTimeStep(String username, String expectedBase32Secret, long timeStep) {
            TotpCredential credential = active.get(username);
            if (credential == null
                    || !credential.base32Secret().equals(expectedBase32Secret)
                    || timeStep <= credential.lastAcceptedTimeStep()) {
                return false;
            }
            active.put(username, new TotpCredential(expectedBase32Secret, timeStep));
            return true;
        }

        @Override
        public synchronized boolean remove(String username) {
            pending.remove(username);
            pendingFailures.remove(username);
            return active.remove(username) != null;
        }

        private record Pending(String secret, Instant expiresAt) {}
    }
}

package io.zhijun.security.autoconfigure;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import io.zhijun.security.core.TotpCredential;
import io.zhijun.security.core.TotpCredentialStore;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base32;

/** TOTP enrollment and verification logic; persistence and secret encryption remain host-owned. */
public class TotpMfaService {

    private static final Duration TIME_STEP = Duration.ofSeconds(30);
    private static final long CLOCK_SKEW_STEPS = 1;
    private static final int SECRET_LENGTH_BYTES = 20;
    private static final int OTP_LENGTH = 6;
    private static final TimeBasedOneTimePasswordGenerator GENERATOR = new TimeBasedOneTimePasswordGenerator();
    private static final Base32 BASE32 = new Base32();

    private final TotpCredentialStore store;
    private final SecureRandom secureRandom;
    private final Clock clock;
    private final Duration enrollmentTtl;
    private final int maximumConfirmationAttempts;

    public TotpMfaService(
            TotpCredentialStore store,
            SecureRandom secureRandom,
            Clock clock,
            Duration enrollmentTtl,
            int maximumConfirmationAttempts) {
        this.store = Objects.requireNonNull(store);
        this.secureRandom = Objects.requireNonNull(secureRandom);
        this.clock = Objects.requireNonNull(clock);
        this.enrollmentTtl = Objects.requireNonNull(enrollmentTtl);
        this.maximumConfirmationAttempts = maximumConfirmationAttempts;
        if (enrollmentTtl.isZero() || enrollmentTtl.isNegative()) {
            throw new IllegalArgumentException("TOTP enrollment TTL must be positive");
        }
        if (maximumConfirmationAttempts < 1) {
            throw new IllegalArgumentException("TOTP confirmation attempt limit must be positive");
        }
    }

    /** Generates a new secret and stores it as pending; callers must display the returned secret only once. */
    public Enrollment beginEnrollment(String username, String issuer) {
        if (username == null || username.isBlank() || issuer == null || issuer.isBlank()) {
            throw new IllegalArgumentException("Username and TOTP issuer are required");
        }
        byte[] secretBytes = new byte[SECRET_LENGTH_BYTES];
        secureRandom.nextBytes(secretBytes);
        try {
            String secret = BASE32.encodeToString(secretBytes);
            Instant expiresAt = clock.instant().plus(enrollmentTtl);
            store.savePending(username, secret, expiresAt);
            String label = encodeUriComponent(issuer) + ":" + encodeUriComponent(username);
            String uri = "otpauth://totp/" + label + "?secret=" + secret + "&issuer="
                    + encodeUriComponent(issuer)
                    + "&algorithm=SHA1&digits=" + OTP_LENGTH + "&period=" + TIME_STEP.toSeconds();
            return new Enrollment(secret, uri, expiresAt);
        } finally {
            Arrays.fill(secretBytes, (byte) 0);
        }
    }

    /** Activates a pending secret only after a valid enrollment code is confirmed. */
    public boolean confirmEnrollment(String username, String code) {
        Instant now = clock.instant();
        Optional<String> pendingSecret = store.findPendingSecret(username, now);
        if (pendingSecret.isEmpty()) {
            return false;
        }
        OptionalLong matchedStep = matchingStep(pendingSecret.get(), code, now);
        if (matchedStep.isEmpty()) {
            store.recordPendingConfirmationFailure(username, maximumConfirmationAttempts, now);
            return false;
        }
        return store.activatePending(username, pendingSecret.get(), matchedStep.getAsLong(), now);
    }

    /** Validates one active authenticator code and atomically consumes its time step. */
    public boolean verify(String username, String code) {
        if (!validCodeFormat(code)) {
            return false;
        }
        Optional<TotpCredential> credential = store.findActive(username);
        if (credential.isEmpty()) {
            return false;
        }
        Instant now = clock.instant();
        OptionalLong matchedStep = matchingStep(credential.get().base32Secret(), code, now);
        return matchedStep.isPresent()
                && matchedStep.getAsLong() > credential.get().lastAcceptedTimeStep()
                && store.consumeTimeStep(username, credential.get().base32Secret(), matchedStep.getAsLong());
    }

    public boolean remove(String username) {
        return store.remove(username);
    }

    public boolean isEnrolled(String username) {
        return store.findActive(username).isPresent();
    }

    private static OptionalLong matchingStep(String base32Secret, String code, Instant now) {
        if (!validCodeFormat(code)) {
            return OptionalLong.empty();
        }
        byte[] keyBytes;
        try {
            keyBytes = BASE32.decode(base32Secret);
        } catch (IllegalArgumentException exception) {
            return OptionalLong.empty();
        }
        try {
            long currentStep = Math.floorDiv(now.getEpochSecond(), TIME_STEP.toSeconds());
            for (long candidate = currentStep + CLOCK_SKEW_STEPS;
                    candidate >= currentStep - CLOCK_SKEW_STEPS;
                    candidate--) {
                String expected = GENERATOR.generateOneTimePasswordString(
                        new SecretKeySpec(keyBytes, "HmacSHA1"),
                        Instant.ofEpochSecond(candidate * TIME_STEP.toSeconds()),
                        Locale.ROOT);
                if (MessageDigest.isEqual(
                        code.getBytes(StandardCharsets.US_ASCII), expected.getBytes(StandardCharsets.US_ASCII))) {
                    return OptionalLong.of(candidate);
                }
            }
            return OptionalLong.empty();
        } catch (java.security.InvalidKeyException exception) {
            throw new IllegalStateException("Could not validate TOTP credential", exception);
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
        }
    }

    private static boolean validCodeFormat(String code) {
        return code != null && code.matches("[0-9]{6}");
    }

    private static String encodeUriComponent(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    public record Enrollment(String secret, String otpauthUri, Instant expiresAt) {

        @Override
        public String toString() {
            return "Enrollment[secret=<redacted>, otpauthUri=<redacted>, expiresAt=" + expiresAt + "]";
        }
    }
}

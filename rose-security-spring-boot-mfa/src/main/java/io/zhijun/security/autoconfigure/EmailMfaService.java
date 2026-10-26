package io.zhijun.security.autoconfigure;

import io.zhijun.security.core.EmailMfaStore;
import io.zhijun.security.core.MfaEmailSender;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Objects;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Email MFA challenge lifecycle; the host owns delivery and persistence. */
public class EmailMfaService {

    private static final int CODE_BOUND = 1_000_000;
    private final EmailMfaStore store;
    private final MfaEmailSender sender;
    private final SecureRandom secureRandom;

    public EmailMfaService(EmailMfaStore store, MfaEmailSender sender, SecureRandom secureRandom) {
        this.store = Objects.requireNonNull(store);
        this.sender = Objects.requireNonNull(sender);
        this.secureRandom = Objects.requireNonNull(secureRandom);
    }

    public void beginLogin(String username, String transactionToken, Instant expiresAt) {
        send(username, transactionToken, "login", expiresAt);
    }

    /** Starts user-initiated enrollment and returns the short-lived token needed to confirm it. */
    public Challenge beginEnrollment(String username, Duration ttl, Instant now) {
        return beginChallenge(username, "enrollment", ttl, now);
    }

    public Challenge beginRemoval(String username, Duration ttl, Instant now) {
        return beginChallenge(username, "removal", ttl, now);
    }

    private Challenge beginChallenge(String username, String purpose, Duration ttl, Instant now) {
        String token = randomToken();
        Instant expiresAt = now.plus(ttl);
        send(username, token, purpose, expiresAt);
        return new Challenge(token, expiresAt);
    }

    public boolean verifyLogin(String username, String transactionToken, String code, Instant now) {
        return consume(username, transactionToken, "login", code, now);
    }

    public boolean isEnabled(String username) {
        return store.isEnabled(username);
    }

    public boolean confirmEnrollment(String username, String token, String code, Instant now, int maximumAttempts) {
        return verifyManagement(username, token, "enrollment", code, now, maximumAttempts, true);
    }

    public boolean confirmRemoval(String username, String token, String code, Instant now, int maximumAttempts) {
        return verifyManagement(username, token, "removal", code, now, maximumAttempts, false);
    }

    private boolean verifyManagement(
            String username,
            String token,
            String purpose,
            String code,
            Instant now,
            int maximumAttempts,
            boolean enabledAfterConsume) {
        if (username == null || token == null || token.isBlank() || maximumAttempts < 1) return false;
        if (consumeAndSetEnabled(username, token, purpose, code, now, enabledAfterConsume)) return true;
        store.recordFailedAttempt(username, challengeId(token), purpose, now, maximumAttempts);
        return false;
    }

    private void send(String username, String token, String purpose, Instant expiresAt) {
        if (username == null || username.isBlank() || token == null || token.isBlank()) {
            throw new IllegalArgumentException("Email username and MFA challenge token are required");
        }
        String code = String.format(Locale.ROOT, "%06d", secureRandom.nextInt(CODE_BOUND));
        store.saveChallenge(username, challengeId(token), purpose, proofHash(token, purpose, code), expiresAt);
        sender.send(username, code, expiresAt);
    }

    private boolean consume(String username, String token, String purpose, String code, Instant now) {
        if (username == null || token == null || token.isBlank() || code == null || !code.matches("[0-9]{6}")) {
            return false;
        }
        return store.consumeChallenge(username, challengeId(token), purpose, proofHash(token, purpose, code), now);
    }

    private boolean consumeAndSetEnabled(
            String username, String token, String purpose, String code, Instant now, boolean enabled) {
        if (username == null || token == null || token.isBlank() || code == null || !code.matches("[0-9]{6}")) {
            return false;
        }
        return store.consumeChallengeAndSetEnabled(
                username, challengeId(token), purpose, proofHash(token, purpose, code), now, enabled);
    }

    private String randomToken() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String challengeId(String token) {
        try {
            return HexFormat.of()
                    .formatHex(MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required for email MFA", exception);
        }
    }

    /** A transaction-keyed HMAC prevents offline code guessing from the challenge store alone. */
    private static String proofHash(String token, String purpose, String code) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(token.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal((purpose + ":" + code).getBytes(StandardCharsets.US_ASCII)));
        } catch (java.security.GeneralSecurityException exception) {
            throw new IllegalStateException("HmacSHA256 is required for email MFA", exception);
        }
    }

    public record Challenge(String token, Instant expiresAt) {

        @Override
        public String toString() {
            return "Challenge[token=<redacted>, expiresAt=" + expiresAt + "]";
        }
    }
}

package io.zhijun.security.sample;

import io.zhijun.security.core.EmailMfaStore;
import io.zhijun.security.core.MfaLoginTransaction;
import io.zhijun.security.core.MfaLoginTransactionStore;
import io.zhijun.security.core.TotpCredential;
import io.zhijun.security.core.TotpCredentialStore;
import io.zhijun.security.core.WebAuthnMfaChallenge;
import io.zhijun.security.core.WebAuthnMfaChallengeStore;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.springframework.stereotype.Component;

/** Volatile demo-only MFA store. Production stores must encrypt TOTP secrets at rest. */
@Component
public class SampleMfaStore
        implements TotpCredentialStore, MfaLoginTransactionStore, EmailMfaStore, WebAuthnMfaChallengeStore {

    private final Map<String, PendingTotp> pendingTotp = new HashMap<>();
    private final Map<String, TotpCredential> activeTotp = new HashMap<>();
    private final Map<String, PendingLogin> loginTransactions = new HashMap<>();
    private final Map<ChallengeKey, EmailChallenge> emailChallenges = new HashMap<>();
    private final Set<String> enabledEmailMfa = new HashSet<>();
    private final Map<String, WebAuthnMfaChallenge> webAuthnChallenges = new HashMap<>();

    @Override
    public synchronized void save(String tokenHash, WebAuthnMfaChallenge challenge) {
        webAuthnChallenges.put(tokenHash, challenge);
    }

    @Override
    public synchronized Optional<WebAuthnMfaChallenge> consume(
            String tokenHash, String username, String operation, String transactionTokenHash, Instant now) {
        WebAuthnMfaChallenge challenge = webAuthnChallenges.get(tokenHash);
        if (challenge == null
                || !challenge.username().equals(username)
                || !challenge.operation().equals(operation)
                || !java.util.Objects.equals(challenge.transactionTokenHash(), transactionTokenHash)) {
            return Optional.empty();
        }
        webAuthnChallenges.remove(tokenHash);
        if (!challenge.expiresAt().isAfter(now)) return Optional.empty();
        return Optional.of(challenge);
    }

    @Override
    public synchronized void saveChallenge(
            String username, String challengeId, String purpose, String proofHash, Instant expiresAt) {
        emailChallenges.put(
                new ChallengeKey(username, challengeId, purpose), new EmailChallenge(proofHash, expiresAt, 0));
    }

    @Override
    public synchronized boolean consumeChallenge(
            String username, String challengeId, String purpose, String expectedProofHash, Instant now) {
        ChallengeKey key = new ChallengeKey(username, challengeId, purpose);
        EmailChallenge challenge = emailChallenges.get(key);
        if (challenge == null || !challenge.expiresAt().isAfter(now)) {
            emailChallenges.remove(key);
            return false;
        }
        if (!java.security.MessageDigest.isEqual(
                challenge.proofHash().getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                expectedProofHash.getBytes(java.nio.charset.StandardCharsets.US_ASCII))) {
            return false;
        }
        emailChallenges.remove(key);
        return true;
    }

    @Override
    public synchronized boolean consumeChallengeAndSetEnabled(
            String username,
            String challengeId,
            String purpose,
            String expectedProofHash,
            Instant now,
            boolean enabled) {
        ChallengeKey key = new ChallengeKey(username, challengeId, purpose);
        EmailChallenge challenge = emailChallenges.get(key);
        if (challenge == null || !challenge.expiresAt().isAfter(now)) {
            emailChallenges.remove(key);
            return false;
        }
        if (!java.security.MessageDigest.isEqual(
                challenge.proofHash().getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                expectedProofHash.getBytes(java.nio.charset.StandardCharsets.US_ASCII))) {
            return false;
        }
        emailChallenges.remove(key);
        if (enabled) enabledEmailMfa.add(username);
        else enabledEmailMfa.remove(username);
        return true;
    }

    @Override
    public synchronized boolean recordFailedAttempt(
            String username, String challengeId, String purpose, Instant now, int maximumAttempts) {
        ChallengeKey key = new ChallengeKey(username, challengeId, purpose);
        EmailChallenge challenge = emailChallenges.get(key);
        if (challenge == null || !challenge.expiresAt().isAfter(now)) {
            emailChallenges.remove(key);
            return false;
        }
        int failures = challenge.failures() + 1;
        if (failures >= maximumAttempts) {
            emailChallenges.remove(key);
            return false;
        }
        emailChallenges.put(key, new EmailChallenge(challenge.proofHash(), challenge.expiresAt(), failures));
        return true;
    }

    @Override
    public synchronized boolean isEnabled(String username) {
        return enabledEmailMfa.contains(username);
    }

    synchronized void clearEmailMfa(String username) {
        enabledEmailMfa.remove(username);
        emailChallenges.keySet().removeIf(key -> key.username().equals(username));
    }

    @Override
    public synchronized void savePending(String username, String base32Secret, Instant expiresAt) {
        pendingTotp.put(username, new PendingTotp(base32Secret, expiresAt, 0));
    }

    @Override
    public synchronized Optional<String> findPendingSecret(String username, Instant now) {
        PendingTotp pending = pendingTotp.get(username);
        return pending != null && pending.expiresAt().isAfter(now) ? Optional.of(pending.secret()) : Optional.empty();
    }

    @Override
    public synchronized boolean recordPendingConfirmationFailure(String username, int maximumAttempts, Instant now) {
        PendingTotp pending = pendingTotp.get(username);
        if (pending == null || !pending.expiresAt().isAfter(now)) {
            pendingTotp.remove(username);
            return false;
        }
        int failures = pending.failures() + 1;
        if (failures >= maximumAttempts) {
            pendingTotp.remove(username);
            return false;
        }
        pendingTotp.put(username, new PendingTotp(pending.secret(), pending.expiresAt(), failures));
        return true;
    }

    @Override
    public synchronized boolean activatePending(
            String username, String expectedBase32Secret, long acceptedTimeStep, Instant now) {
        PendingTotp pending = pendingTotp.get(username);
        if (pending == null
                || !pending.expiresAt().isAfter(now)
                || !pending.secret().equals(expectedBase32Secret)) {
            return false;
        }
        activeTotp.put(username, new TotpCredential(expectedBase32Secret, acceptedTimeStep));
        pendingTotp.remove(username);
        return true;
    }

    @Override
    public synchronized Optional<TotpCredential> findActive(String username) {
        return Optional.ofNullable(activeTotp.get(username));
    }

    @Override
    public synchronized boolean consumeTimeStep(String username, String expectedBase32Secret, long timeStep) {
        TotpCredential current = activeTotp.get(username);
        if (current == null
                || !current.base32Secret().equals(expectedBase32Secret)
                || timeStep <= current.lastAcceptedTimeStep()) {
            return false;
        }
        activeTotp.put(username, new TotpCredential(expectedBase32Secret, timeStep));
        return true;
    }

    @Override
    public synchronized boolean remove(String username) {
        pendingTotp.remove(username);
        return activeTotp.remove(username) != null;
    }

    @Override
    public synchronized void create(String tokenHash, MfaLoginTransaction transaction) {
        loginTransactions.put(tokenHash, new PendingLogin(transaction, 0, false));
    }

    @Override
    public synchronized Optional<MfaLoginTransaction> findActive(String tokenHash, Instant now) {
        PendingLogin pending = loginTransactions.get(tokenHash);
        return pending != null
                        && !pending.consumed()
                        && pending.transaction().expiresAt().isAfter(now)
                ? Optional.of(pending.transaction())
                : Optional.empty();
    }

    @Override
    public synchronized boolean consume(String tokenHash, Instant now) {
        PendingLogin pending = loginTransactions.get(tokenHash);
        if (pending == null
                || pending.consumed()
                || !pending.transaction().expiresAt().isAfter(now)) {
            return false;
        }
        loginTransactions.put(tokenHash, new PendingLogin(pending.transaction(), pending.failures(), true));
        return true;
    }

    @Override
    public synchronized boolean recordFailedAttempt(String tokenHash, Instant now, int maximumAttempts) {
        PendingLogin pending = loginTransactions.get(tokenHash);
        if (pending == null
                || pending.consumed()
                || !pending.transaction().expiresAt().isAfter(now)) {
            return false;
        }
        int failures = pending.failures() + 1;
        loginTransactions.put(
                tokenHash, new PendingLogin(pending.transaction(), failures, failures >= maximumAttempts));
        return failures < maximumAttempts;
    }

    private record PendingTotp(String secret, Instant expiresAt, int failures) {}

    private record PendingLogin(MfaLoginTransaction transaction, int failures, boolean consumed) {}

    private record ChallengeKey(String username, String challengeId, String purpose) {}

    private record EmailChallenge(String proofHash, Instant expiresAt, int failures) {}
}

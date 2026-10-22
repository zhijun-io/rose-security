package io.zhijun.security.core;

import java.time.Instant;
import java.util.Optional;

/** Persistence boundary for one TOTP authenticator per user. Implementations must encrypt secrets at rest. */
public interface TotpCredentialStore {

    /** Stores/replaces a short-lived enrollment secret without activating it. */
    void savePending(String username, String base32Secret, Instant expiresAt);

    /** Returns a pending secret only while its enrollment is valid. */
    Optional<String> findPendingSecret(String username, Instant now);

    /** Atomically records a bad proof; returns false if the pending enrollment is now invalid or unavailable. */
    boolean recordPendingConfirmationFailure(String username, int maximumAttempts, Instant now);

    /** Atomically activates the matching pending secret and records the confirming step as already used. */
    boolean activatePending(String username, String expectedBase32Secret, long acceptedTimeStep, Instant now);

    /** Returns the user's active decrypted secret and its last accepted step. */
    Optional<TotpCredential> findActive(String username);

    /** Atomically accepts a step only if it is newer than the user's last accepted step and the secret still matches. */
    boolean consumeTimeStep(String username, String expectedBase32Secret, long timeStep);

    /** Removes the active credential and any pending enrollment. */
    boolean remove(String username);
}

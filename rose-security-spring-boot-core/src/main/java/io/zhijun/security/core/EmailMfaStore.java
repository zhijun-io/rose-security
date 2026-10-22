package io.zhijun.security.core;

import java.time.Instant;

/** Stores enabled email MFA state and one-time email challenges. */
public interface EmailMfaStore {

    /** Stores a challenge under an opaque identifier, bound to a user and purpose. */
    void saveChallenge(String username, String challengeId, String purpose, String proofHash, Instant expiresAt);

    /** Atomically matches and consumes an unexpired challenge. */
    boolean consumeChallenge(
            String username, String challengeId, String purpose, String expectedProofHash, Instant now);

    /** Atomically consumes an enrollment/removal challenge and updates the user's enabled state. */
    boolean consumeChallengeAndSetEnabled(
            String username,
            String challengeId,
            String purpose,
            String expectedProofHash,
            Instant now,
            boolean enabled);

    /** Records a failed management proof and invalidates it at the configured limit. */
    boolean recordFailedAttempt(String username, String challengeId, String purpose, Instant now, int maximumAttempts);

    boolean isEnabled(String username);
}

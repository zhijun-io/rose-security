package io.zhijun.security.core;

import java.time.Instant;
import java.util.Optional;

/** Persistence boundary for short-lived MFA login transactions, keyed by a token hash. */
public interface MfaLoginTransactionStore {

    /** Stores transaction state under the hash of its opaque bearer token. */
    void create(String tokenHash, MfaLoginTransaction transaction);

    /** Returns only an unexpired, unconsumed transaction. */
    Optional<MfaLoginTransaction> findActive(String tokenHash, Instant now);

    /** Atomically consumes an unexpired transaction; only one concurrent caller may succeed. */
    boolean consume(String tokenHash, Instant now);

    /** Atomically records a failed proof and invalidates the transaction at the configured attempt limit. */
    boolean recordFailedAttempt(String tokenHash, Instant now, int maximumAttempts);
}

package io.zhijun.security.core;

import java.time.Instant;
import java.util.Optional;

/** Persistence boundary for one-time WebAuthn challenges. Implementations must consume atomically. */
public interface WebAuthnMfaChallengeStore {

    void save(String tokenHash, WebAuthnMfaChallenge challenge);

    Optional<WebAuthnMfaChallenge> consume(
            String tokenHash, String username, String operation, String transactionTokenHash, Instant now);
}

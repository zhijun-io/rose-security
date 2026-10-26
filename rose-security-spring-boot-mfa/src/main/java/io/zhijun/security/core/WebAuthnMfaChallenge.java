package io.zhijun.security.core;

import java.time.Instant;

/** A short-lived WebAuthn ceremony bound to a user and operation. */
public record WebAuthnMfaChallenge(
        String username, String operation, String transactionTokenHash, byte[] options, Instant expiresAt) {

    public WebAuthnMfaChallenge {
        options = options.clone();
    }

    @Override
    public byte[] options() {
        return options.clone();
    }
}

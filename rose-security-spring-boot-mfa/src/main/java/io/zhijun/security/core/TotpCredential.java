package io.zhijun.security.core;

import java.util.Objects;

/** Active TOTP credential returned decrypted for verification; stores must protect it at rest. */
public record TotpCredential(String base32Secret, long lastAcceptedTimeStep) {

    public TotpCredential {
        Objects.requireNonNull(base32Secret);
        if (base32Secret.isBlank() || lastAcceptedTimeStep < -1) {
            throw new IllegalArgumentException("Invalid TOTP credential");
        }
    }

    @Override
    public String toString() {
        return "TotpCredential[base32Secret=<redacted>, lastAcceptedTimeStep=" + lastAcceptedTimeStep + "]";
    }
}

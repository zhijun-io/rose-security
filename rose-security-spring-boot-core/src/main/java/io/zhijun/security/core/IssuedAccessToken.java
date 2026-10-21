package io.zhijun.security.core;

import java.time.Instant;
import java.util.Objects;

/** A short-lived access token returned by the configured issuer. */
public record IssuedAccessToken(String value, Instant issuedAt, Instant expiresAt) {

    public IssuedAccessToken {
        Objects.requireNonNull(value, "value must not be null");
        Objects.requireNonNull(issuedAt, "issuedAt must not be null");
        Objects.requireNonNull(expiresAt, "expiresAt must not be null");
        if (value.isBlank() || !expiresAt.isAfter(issuedAt)) {
            throw new IllegalArgumentException("A token value and a positive lifetime are required");
        }
    }

    @Override
    public String toString() {
        return "IssuedAccessToken[value=<redacted>, issuedAt=" + issuedAt + ", expiresAt=" + expiresAt + "]";
    }
}

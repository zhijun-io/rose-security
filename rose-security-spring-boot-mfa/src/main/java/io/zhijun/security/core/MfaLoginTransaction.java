package io.zhijun.security.core;

import java.time.Instant;
import java.util.Objects;
import java.util.Set;

/** Non-secret state for a primary-authenticated login awaiting MFA completion. */
public record MfaLoginTransaction(
        String username,
        Set<String> allowedMethods,
        Set<String> authenticationMethods,
        Instant createdAt,
        Instant expiresAt,
        UserSessionClientInfo clientInfo) {

    public MfaLoginTransaction {
        Objects.requireNonNull(username);
        allowedMethods = Set.copyOf(allowedMethods);
        authenticationMethods = Set.copyOf(authenticationMethods);
        Objects.requireNonNull(createdAt);
        Objects.requireNonNull(expiresAt);
        if (!expiresAt.isAfter(createdAt)) {
            throw new IllegalArgumentException("MFA transaction expiry must be after creation");
        }
    }

    @Override
    public String toString() {
        return "MfaLoginTransaction[username=<redacted>, allowedMethods=" + allowedMethods
                + ", authenticationMethods=" + authenticationMethods
                + ", createdAt=" + createdAt
                + ", expiresAt=" + expiresAt
                + ", clientInfo=<redacted>]";
    }
}

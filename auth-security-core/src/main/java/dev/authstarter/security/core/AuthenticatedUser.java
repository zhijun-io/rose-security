package dev.authstarter.security.core;

import java.util.Objects;

/** Minimal authentication identity; application roles and business attributes stay outside the starter. */
public record AuthenticatedUser(String userId, String email, long securityVersion) {

    public AuthenticatedUser {
        Objects.requireNonNull(userId, "userId must not be null");
        if (userId.isBlank()) {
            throw new IllegalArgumentException("userId must not be blank");
        }
        Objects.requireNonNull(email, "email must not be null");
        if (email.isBlank()) {
            throw new IllegalArgumentException("email must not be blank");
        }
        if (securityVersion < 0) {
            throw new IllegalArgumentException("securityVersion must not be negative");
        }
    }
}

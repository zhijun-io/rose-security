package dev.authstarter.security.core;

/** Security-relevant user state supplied by the host application. */
public record UserSecurityState(String userId, boolean enabled, long securityVersion) {

    public UserSecurityState {
        if (userId == null || userId.isBlank()) {
            throw new IllegalArgumentException("userId must not be null or blank");
        }
        if (securityVersion < 0) {
            throw new IllegalArgumentException("securityVersion must not be negative");
        }
    }
}

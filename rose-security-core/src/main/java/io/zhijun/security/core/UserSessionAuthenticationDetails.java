package io.zhijun.security.core;

import java.time.Instant;
import java.util.Set;

/** Verified authentication context consumed when the token session is created. */
public record UserSessionAuthenticationDetails(
        Set<String> authenticationMethods, Instant authenticatedAt, UserSessionClientInfo clientInfo) {
    public UserSessionAuthenticationDetails {
        authenticationMethods = Set.copyOf(authenticationMethods);
    }
}

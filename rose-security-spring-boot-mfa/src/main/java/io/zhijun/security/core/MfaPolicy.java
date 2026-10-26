package io.zhijun.security.core;

import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/** MFA methods currently enrolled by a Spring Security user and allowed for login. */
public record MfaPolicy(boolean enabled, Set<String> methods, Duration transactionTtl) {

    public MfaPolicy {
        methods = methods == null ? Set.of() : Collections.unmodifiableSet(new LinkedHashSet<>(methods));
        if (methods.stream().anyMatch(method -> method == null || !method.matches("[a-z][a-z0-9-]{0,31}"))) {
            throw new IllegalArgumentException("MFA method names must be lower-case identifiers");
        }
        if (transactionTtl == null || transactionTtl.isZero() || transactionTtl.isNegative()) {
            throw new IllegalArgumentException("MFA transaction TTL must be positive");
        }
    }
}

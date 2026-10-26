package io.zhijun.security.autoconfigure;

import io.zhijun.security.core.MfaLoginTransaction;
import java.time.Instant;
import java.util.Objects;

record MfaLoginCompletion(MfaLoginTransaction transaction, String method, Instant authenticatedAt) {

    MfaLoginCompletion {
        Objects.requireNonNull(transaction);
        Objects.requireNonNull(method);
        Objects.requireNonNull(authenticatedAt);
    }
}

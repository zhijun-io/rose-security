package io.zhijun.security.core;

import java.time.Instant;

/** Host-provided delivery for an email MFA code. Implementations must not log the code. */
@FunctionalInterface
public interface MfaEmailSender {

    void send(String email, String code, Instant expiresAt);
}

package io.zhijun.security.core;

import java.time.Instant;

/** Read-only session information exposed by the token-session service. */
public record UserSessionView(
        String sessionId,
        Instant createdAt,
        Instant lastUsedAt,
        Instant expiresAt,
        Instant absoluteExpiresAt,
        String clientIp,
        String device) {}

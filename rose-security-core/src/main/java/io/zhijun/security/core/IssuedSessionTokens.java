package io.zhijun.security.core;

import java.time.Instant;
import java.util.Objects;

/** One-time HTTP response material for an authenticated session. */
public record IssuedSessionTokens(
        String accessToken,
        Instant accessTokenExpiresAt,
        String refreshToken,
        Instant refreshTokenExpiresAt,
        String sessionId) {

    public IssuedSessionTokens {
        Objects.requireNonNull(accessToken, "accessToken must not be null");
        Objects.requireNonNull(accessTokenExpiresAt, "accessTokenExpiresAt must not be null");
        Objects.requireNonNull(sessionId, "sessionId must not be null");
        if ((refreshToken == null) != (refreshTokenExpiresAt == null)) {
            throw new IllegalArgumentException(
                    "Refresh token and expiry must either both be present or both be absent");
        }
    }

    @Override
    public String toString() {
        return "IssuedSessionTokens[accessToken=<redacted>, refreshToken=<redacted>, accessTokenExpiresAt="
                + accessTokenExpiresAt
                + ", refreshTokenExpiresAt="
                + refreshTokenExpiresAt
                + ", sessionId="
                + sessionId
                + "]";
    }
}

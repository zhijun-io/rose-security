package io.zhijun.security.autoconfigure;

import io.zhijun.security.core.IssuedSessionTokens;
import java.util.List;
import java.util.Objects;
import org.springframework.security.authentication.AbstractAuthenticationToken;

/** Authentication request/result used by the refresh filter and custom refresh converters. */
public class RefreshRequestAuthenticationToken extends AbstractAuthenticationToken {

    private final String refreshToken;
    private final IssuedSessionTokens tokens;

    protected RefreshRequestAuthenticationToken(String refreshToken) {
        super(List.of());
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new IllegalArgumentException("refreshToken must not be blank");
        }
        this.refreshToken = refreshToken;
        this.tokens = null;
        setAuthenticated(false);
    }

    protected RefreshRequestAuthenticationToken(IssuedSessionTokens tokens) {
        super(List.of());
        this.refreshToken = null;
        this.tokens = Objects.requireNonNull(tokens, "tokens must not be null");
        setAuthenticated(true);
    }

    public static RefreshRequestAuthenticationToken unauthenticated(String refreshToken) {
        return new RefreshRequestAuthenticationToken(refreshToken);
    }

    public static RefreshRequestAuthenticationToken authenticated(IssuedSessionTokens tokens) {
        return new RefreshRequestAuthenticationToken(tokens);
    }

    public String refreshToken() {
        if (isAuthenticated()) {
            throw new IllegalStateException("Authenticated refresh requests do not expose a refresh token");
        }
        return refreshToken;
    }

    public IssuedSessionTokens tokens() {
        return tokens;
    }

    @Override
    public Object getCredentials() {
        return "<redacted>";
    }

    @Override
    public Object getPrincipal() {
        return tokens == null ? "refresh-token" : tokens.sessionId();
    }

    @Override
    public String toString() {
        return "RefreshRequestAuthenticationToken[refreshToken=<redacted>, authenticated=" + isAuthenticated() + "]";
    }
}

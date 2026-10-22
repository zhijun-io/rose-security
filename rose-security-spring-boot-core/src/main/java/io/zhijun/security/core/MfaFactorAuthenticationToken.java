package io.zhijun.security.core;

import java.util.List;
import java.util.Objects;
import org.springframework.security.authentication.AbstractAuthenticationToken;

/** Unauthenticated proof submitted for an MFA factor; factor providers must validate ownership and proof. */
public final class MfaFactorAuthenticationToken extends AbstractAuthenticationToken {

    private final String username;
    private final String method;
    private final String transactionToken;
    private String proof;

    private MfaFactorAuthenticationToken(String username, String method, String proof, String transactionToken) {
        super(List.of());
        this.username = Objects.requireNonNull(username);
        this.method = Objects.requireNonNull(method);
        this.transactionToken = transactionToken;
        this.proof = Objects.requireNonNull(proof);
        super.setAuthenticated(false);
    }

    public static MfaFactorAuthenticationToken unauthenticated(String username, String method, String proof) {
        return new MfaFactorAuthenticationToken(username, method, proof, null);
    }

    public static MfaFactorAuthenticationToken unauthenticated(
            String username, String method, String proof, String transactionToken) {
        return new MfaFactorAuthenticationToken(username, method, proof, transactionToken);
    }

    public String method() {
        return method;
    }

    public String transactionToken() {
        return transactionToken;
    }

    @Override
    public Object getCredentials() {
        return proof;
    }

    @Override
    public Object getPrincipal() {
        return username;
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        proof = null;
    }

    @Override
    public void setAuthenticated(boolean authenticated) {
        if (authenticated) {
            throw new IllegalArgumentException("Use a factor AuthenticationProvider to authenticate MFA proofs");
        }
        super.setAuthenticated(false);
    }

    @Override
    public String toString() {
        return "MfaFactorAuthenticationToken[username=<redacted>, method=" + method
                + ", proof=<redacted>, transactionToken=<redacted>]";
    }
}

package io.zhijun.security.autoconfigure;

import java.util.List;
import java.util.Objects;
import org.springframework.security.authentication.AbstractAuthenticationToken;

final class MfaVerificationAuthenticationToken extends AbstractAuthenticationToken {

    private final String transactionToken;
    private final String method;
    private String proof;

    private MfaVerificationAuthenticationToken(String transactionToken, String method, String proof) {
        super(List.of());
        this.transactionToken = Objects.requireNonNull(transactionToken);
        this.method = Objects.requireNonNull(method);
        this.proof = Objects.requireNonNull(proof);
        super.setAuthenticated(false);
    }

    static MfaVerificationAuthenticationToken unauthenticated(String transactionToken, String method, String proof) {
        return new MfaVerificationAuthenticationToken(transactionToken, method, proof);
    }

    String transactionToken() {
        return transactionToken;
    }

    String method() {
        return method;
    }

    @Override
    public Object getCredentials() {
        return proof;
    }

    @Override
    public Object getPrincipal() {
        return transactionToken;
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        proof = null;
    }

    @Override
    public void setAuthenticated(boolean authenticated) {
        if (authenticated) {
            throw new IllegalArgumentException("Use the MFA transaction service to authenticate this request");
        }
        super.setAuthenticated(false);
    }

    @Override
    public String toString() {
        return "MfaVerificationAuthenticationToken[transactionToken=<redacted>, method=" + method
                + ", proof=<redacted>]";
    }
}

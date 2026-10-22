package io.zhijun.security.autoconfigure;

import io.zhijun.security.core.MfaFactorAuthenticationToken;
import io.zhijun.security.core.MfaLoginTransaction;
import io.zhijun.security.core.MfaLoginTransactionStore;
import io.zhijun.security.core.MfaPolicy;
import io.zhijun.security.core.UserSessionClientInfo;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Set;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

/** Creates and consumes opaque MFA transactions without persisting their bearer tokens. */
public class MfaLoginTransactionService {

    private final MfaLoginTransactionStore store;
    private final SecureRandom secureRandom;

    public MfaLoginTransactionService(MfaLoginTransactionStore store, SecureRandom secureRandom) {
        this.store = Objects.requireNonNull(store);
        this.secureRandom = Objects.requireNonNull(secureRandom);
    }

    public StartedTransaction begin(
            UserDetails user,
            MfaPolicy policy,
            Collection<String> authenticationMethods,
            UserSessionClientInfo clientInfo,
            Instant now) {
        Objects.requireNonNull(user);
        Objects.requireNonNull(policy);
        Objects.requireNonNull(authenticationMethods);
        Objects.requireNonNull(now);
        if (!policy.enabled() || policy.methods().isEmpty()) {
            throw new IllegalArgumentException("An MFA transaction requires an enabled policy with available methods");
        }

        byte[] randomToken = new byte[32];
        secureRandom.nextBytes(randomToken);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(randomToken);
        String tokenHash = hash(token);
        Instant expiresAt = now.plus(policy.transactionTtl());
        MfaLoginTransaction transaction = new MfaLoginTransaction(
                user.getUsername(), policy.methods(), Set.copyOf(authenticationMethods), now, expiresAt, clientInfo);
        store.create(tokenHash, transaction);
        return new StartedTransaction(token, transaction.allowedMethods(), expiresAt);
    }

    public VerifiedLogin verify(
            String token,
            String method,
            String proof,
            AuthenticationManager factorAuthenticationManager,
            Instant now,
            int maximumAttempts) {
        if (maximumAttempts < 1) {
            throw new IllegalArgumentException("MFA maximum attempts must be positive");
        }
        String tokenHash = hash(token);
        MfaLoginTransaction transaction = store.findActive(tokenHash, now)
                .orElseThrow(() -> new BadCredentialsException("Authentication failed"));
        if (!transaction.allowedMethods().contains(method)) {
            store.recordFailedAttempt(tokenHash, now, maximumAttempts);
            throw new BadCredentialsException("Authentication failed");
        }

        MfaFactorAuthenticationToken factorRequest =
                MfaFactorAuthenticationToken.unauthenticated(transaction.username(), method, proof, token);
        try {
            Authentication result = factorAuthenticationManager.authenticate(factorRequest);
            if (result == null
                    || !result.isAuthenticated()
                    || !(result.getPrincipal() instanceof UserDetails user)
                    || !transaction.username().equals(user.getUsername())) {
                throw new BadCredentialsException("Authentication failed");
            }
            if (!store.consume(tokenHash, now)) {
                throw new BadCredentialsException("Authentication failed");
            }
            return new VerifiedLogin(transaction, result, method);
        } catch (BadCredentialsException exception) {
            store.recordFailedAttempt(tokenHash, now, maximumAttempts);
            throw new BadCredentialsException("Authentication failed");
        } finally {
            factorRequest.eraseCredentials();
        }
    }

    public String usernameFor(String token, String method, Instant now) {
        MfaLoginTransaction transaction = store.findActive(hash(token), now)
                .filter(value -> value.allowedMethods().contains(method))
                .orElseThrow(() -> new BadCredentialsException("Authentication failed"));
        return transaction.username();
    }

    private static String hash(String token) {
        Objects.requireNonNull(token);
        if (token.isBlank()) {
            throw new IllegalArgumentException("MFA transaction token must not be blank");
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required for MFA transaction tokens", exception);
        }
    }

    public record StartedTransaction(String token, Set<String> methods, Instant expiresAt) {

        public StartedTransaction {
            methods = Set.copyOf(methods);
        }

        @Override
        public String toString() {
            return "StartedTransaction[token=<redacted>, methods=" + methods + ", expiresAt=" + expiresAt + "]";
        }
    }

    public record VerifiedLogin(MfaLoginTransaction transaction, Authentication authentication, String method) {

        @Override
        public String toString() {
            return "VerifiedLogin[transaction=<redacted>, authentication=<redacted>, method=" + method + "]";
        }
    }
}

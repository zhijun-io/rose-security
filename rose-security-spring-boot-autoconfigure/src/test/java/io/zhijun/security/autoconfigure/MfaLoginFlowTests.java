package io.zhijun.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.zhijun.security.core.IssuedSessionTokens;
import io.zhijun.security.core.MfaFactorAuthenticationToken;
import io.zhijun.security.core.MfaLoginTransaction;
import io.zhijun.security.core.MfaLoginTransactionStore;
import io.zhijun.security.core.MfaPolicy;
import io.zhijun.security.core.UserSessionClientInfo;
import io.zhijun.security.core.UserSessionService;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import tools.jackson.databind.json.JsonMapper;

class MfaLoginFlowTests {

    private static final Instant NOW = Instant.parse("2026-10-21T12:00:00Z");
    private static final org.springframework.security.core.userdetails.UserDetails USER = User.withUsername(
                    "user@example.test")
            .password("unused")
            .authorities("ROLE_USER")
            .build();
    private static final UserSessionClientInfo CLIENT_INFO = new UserSessionClientInfo("192.0.2.10", "browser");
    private static final MfaPolicy POLICY = new MfaPolicy(true, Set.of("totp"), Duration.ofMinutes(5));

    @Test
    void enrolledFactorReturnsPendingTransactionWithoutCallingTokenHandler() throws Exception {
        InMemoryTransactionStore store = new InMemoryTransactionStore();
        MfaLoginTransactionService transactionService = new MfaLoginTransactionService(store, new SecureRandom());
        AtomicInteger tokenHandlerCalls = new AtomicInteger();
        AuthenticationSuccessHandler tokenHandler =
                (request, response, authentication) -> tokenHandlerCalls.incrementAndGet();
        AuthenticationDetailsSourceStub detailsSource = new AuthenticationDetailsSourceStub();
        MfaAwareLoginSuccessHandler handler = new MfaAwareLoginSuccessHandler(
                tokenHandler,
                user -> POLICY,
                transactionService,
                null,
                failureHandler(),
                detailsSource::buildDetails,
                JsonMapper.builder().build(),
                Clock.fixed(NOW, ZoneOffset.UTC));
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(new MockHttpServletRequest(), response, authenticatedUser());

        assertThat(response.getStatus()).isEqualTo(HttpStatus.ACCEPTED.value());
        assertThat(response.getContentAsString()).contains("mfa_required", "transaction_token", "totp");
        assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
        assertThat(tokenHandlerCalls).hasValue(0);
        assertThat(store.transactions).hasSize(1);
        assertThat(store.transactions.keySet().iterator().next())
                .hasSize(64)
                .doesNotContain(response.getContentAsString());
    }

    @Test
    void enabledMfaWithNoEnrolledMethodsCompletesPasswordLogin() throws Exception {
        AtomicInteger tokenHandlerCalls = new AtomicInteger();
        AuthenticationSuccessHandler tokenHandler =
                (request, response, authentication) -> tokenHandlerCalls.incrementAndGet();
        MfaAwareLoginSuccessHandler handler = new MfaAwareLoginSuccessHandler(
                tokenHandler,
                user -> new MfaPolicy(true, Set.of(), Duration.ofMinutes(5)),
                null,
                null,
                failureHandler(),
                new AuthenticationDetailsSourceStub()::buildDetails,
                JsonMapper.builder().build(),
                Clock.fixed(NOW, ZoneOffset.UTC));
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(new MockHttpServletRequest(), response, authenticatedUser());

        assertThat(tokenHandlerCalls).hasValue(1);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
    }

    @Test
    void successfulFactorVerificationConsumesTransactionExactlyOnce() {
        InMemoryTransactionStore store = new InMemoryTransactionStore();
        MfaLoginTransactionService transactionService = new MfaLoginTransactionService(store, new SecureRandom());
        MfaLoginTransactionService.StartedTransaction started =
                transactionService.begin(USER, POLICY, Set.of("pwd"), CLIENT_INFO, NOW);
        AtomicInteger providerCalls = new AtomicInteger();

        MfaLoginTransactionService.VerifiedLogin verified = transactionService.verify(
                started.token(),
                "totp",
                "123456",
                authentication -> {
                    assertThat(authentication).isInstanceOf(MfaFactorAuthenticationToken.class);
                    assertThat(authentication.getPrincipal()).isEqualTo("user@example.test");
                    providerCalls.incrementAndGet();
                    return UsernamePasswordAuthenticationToken.authenticated(
                            USER, null, AuthorityUtils.createAuthorityList("ROLE_USER"));
                },
                NOW.plusSeconds(1),
                5);

        assertThat(verified.transaction().clientInfo()).isEqualTo(CLIENT_INFO);
        assertThat(verified.method()).isEqualTo("totp");
        assertThat(store.consumed)
                .containsExactly(store.transactions.keySet().iterator().next());
        assertThatThrownBy(() -> transactionService.verify(
                        started.token(),
                        "totp",
                        "123456",
                        authentication -> {
                            providerCalls.incrementAndGet();
                            return UsernamePasswordAuthenticationToken.authenticated(
                                    USER, null, AuthorityUtils.createAuthorityList("ROLE_USER"));
                        },
                        NOW.plusSeconds(2),
                        5))
                .isInstanceOf(BadCredentialsException.class);
        assertThat(providerCalls).hasValue(1);
    }

    @Test
    void tokenSessionUsesMfaCompletionTimeInsteadOfPrimaryAuthenticationStartTime() throws Exception {
        Instant mfaCompletedAt = NOW.plusSeconds(90);
        MfaLoginTransaction transaction = new MfaLoginTransaction(
                USER.getUsername(), Set.of("totp"), Set.of("pwd"), NOW, NOW.plusSeconds(300), CLIENT_INFO);
        AtomicReference<Instant> capturedAuthenticatedAt = new AtomicReference<>();
        UserSessionService sessionService = new UserSessionService() {
            @Override
            public IssuedSessionTokens create(
                    org.springframework.security.core.userdetails.UserDetails principal,
                    java.util.Collection<String> authenticationMethods,
                    Instant authenticatedAt,
                    UserSessionClientInfo clientInfo) {
                capturedAuthenticatedAt.set(authenticatedAt);
                return new IssuedSessionTokens("access", NOW.plusSeconds(60), null, null, "session");
            }

            @Override
            public IssuedSessionTokens refresh(String refreshToken) {
                throw new UnsupportedOperationException();
            }

            @Override
            public boolean revoke(String username, String sessionId) {
                throw new UnsupportedOperationException();
            }

            @Override
            public int revokeAll(String username) {
                throw new UnsupportedOperationException();
            }

            @Override
            public java.util.List<io.zhijun.security.core.UserSessionView> findActiveSessions(String username) {
                throw new UnsupportedOperationException();
            }
        };
        TokenAuthenticationSuccessHandler handler = new TokenAuthenticationSuccessHandler(
                sessionService,
                request -> CLIENT_INFO,
                failureHandler(),
                JsonMapper.builder().build(),
                Clock.fixed(mfaCompletedAt, ZoneOffset.UTC));
        UsernamePasswordAuthenticationToken authentication = UsernamePasswordAuthenticationToken.authenticated(
                USER, null, AuthorityUtils.createAuthorityList("ROLE_USER"));
        authentication.setDetails(new MfaLoginCompletion(transaction, "totp", mfaCompletedAt));

        handler.tokensFor(new MockHttpServletRequest(), new MockHttpServletResponse(), authentication);

        assertThat(capturedAuthenticatedAt).hasValue(mfaCompletedAt);
        assertThat(capturedAuthenticatedAt.get()).isAfter(transaction.createdAt());
    }

    @Test
    void failedFactorProofIncrementsAttemptCountAndDoesNotConsumeTransaction() {
        InMemoryTransactionStore store = new InMemoryTransactionStore();
        MfaLoginTransactionService transactionService = new MfaLoginTransactionService(store, new SecureRandom());
        MfaLoginTransactionService.StartedTransaction started =
                transactionService.begin(USER, POLICY, Set.of("pwd"), CLIENT_INFO, NOW);

        assertThatThrownBy(() -> transactionService.verify(
                        started.token(),
                        "totp",
                        "000000",
                        authentication -> {
                            throw new BadCredentialsException("Authentication failed");
                        },
                        NOW.plusSeconds(1),
                        2))
                .isInstanceOf(BadCredentialsException.class);

        assertThat(store.failedAttempts).containsValue(1);
        assertThat(store.consumed).isEmpty();
    }

    private static Authentication authenticatedUser() {
        return UsernamePasswordAuthenticationToken.authenticated(
                USER, "secret-password", AuthorityUtils.createAuthorityList("ROLE_USER"));
    }

    private static AuthenticationFailureHandler failureHandler() {
        return new AuthenticationEntryPointFailureHandler(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));
    }

    private static final class AuthenticationDetailsSourceStub {

        private UserSessionClientInfo buildDetails(jakarta.servlet.http.HttpServletRequest request) {
            return CLIENT_INFO;
        }
    }

    private static final class InMemoryTransactionStore implements MfaLoginTransactionStore {

        private final Map<String, MfaLoginTransaction> transactions = new HashMap<>();
        private final Map<String, Integer> failedAttempts = new HashMap<>();
        private final Set<String> consumed = new HashSet<>();
        private final Set<String> invalidated = new HashSet<>();

        @Override
        public synchronized void create(String tokenHash, MfaLoginTransaction transaction) {
            transactions.put(tokenHash, transaction);
        }

        @Override
        public synchronized Optional<MfaLoginTransaction> findActive(String tokenHash, Instant now) {
            if (consumed.contains(tokenHash) || invalidated.contains(tokenHash)) {
                return Optional.empty();
            }
            MfaLoginTransaction transaction = transactions.get(tokenHash);
            return transaction != null && transaction.expiresAt().isAfter(now)
                    ? Optional.of(transaction)
                    : Optional.empty();
        }

        @Override
        public synchronized boolean consume(String tokenHash, Instant now) {
            if (findActive(tokenHash, now).isEmpty()) {
                return false;
            }
            consumed.add(tokenHash);
            return true;
        }

        @Override
        public synchronized boolean recordFailedAttempt(String tokenHash, Instant now, int maximumAttempts) {
            if (findActive(tokenHash, now).isEmpty()) {
                return false;
            }
            int attempts = failedAttempts.merge(tokenHash, 1, Integer::sum);
            if (attempts >= maximumAttempts) {
                invalidated.add(tokenHash);
            }
            return true;
        }
    }
}

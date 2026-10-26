package io.zhijun.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.zhijun.security.core.MfaLoginTransaction;
import io.zhijun.security.core.MfaPolicy;
import io.zhijun.security.core.UserSessionClientInfo;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import tools.jackson.databind.json.JsonMapper;

class MfaAwareLoginSuccessHandlerTests {

    private static final Instant NOW = Instant.parse("2026-10-26T00:00:00Z");
    private static final org.springframework.security.core.userdetails.UserDetails USER = User.withUsername("alice")
            .password("unused")
            .authorities("ROLE_USER")
            .build();
    private static final UserSessionClientInfo CLIENT = new UserSessionClientInfo("192.0.2.1", "test");

    @Test
    void delegatesWhenAuthenticationHasNoUserDetailsPrincipalOrMfaIsDisabled() throws Exception {
        AtomicReference<Authentication> delegated = new AtomicReference<>();
        AuthenticationSuccessHandler handler = handler(
                (request, response, authentication) -> {
                    delegated.set(authentication);
                },
                user -> new MfaPolicy(false, Set.of(), Duration.ofMinutes(5)),
                null,
                null,
                failureHandler());
        var request = new MockHttpServletRequest();
        var response = new MockHttpServletResponse();
        Authentication anonymousPrincipal =
                UsernamePasswordAuthenticationToken.authenticated("principal", null, Set.of());

        handler.onAuthenticationSuccess(request, response, anonymousPrincipal);
        assertThat(delegated).hasValue(anonymousPrincipal);

        handler.onAuthenticationSuccess(request, response, authenticatedUser());
        assertThat(delegated.get().getPrincipal()).isEqualTo(USER);
    }

    @Test
    void reportsMissingTransactionStoreThroughFailureHandler() throws Exception {
        AtomicReference<Exception> failure = new AtomicReference<>();
        AuthenticationFailureHandler failures = (request, response, exception) -> failure.set(exception);
        var handler = handler((request, response, authentication) -> {}, user -> enabledPolicy(), null, null, failures);
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(new MockHttpServletRequest(), response, authenticatedUser());

        assertThat(failure.get()).hasMessageContaining("MFA transaction storage");
        assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
    }

    @Test
    void startsEmailChallengeAndReturnsNoStoreMfaResponse() throws Exception {
        var transactions = mock(MfaLoginTransactionService.class);
        when(transactions.begin(
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.anyCollection(),
                        org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any()))
                .thenReturn(new MfaLoginTransactionService.StartedTransaction(
                        "transaction", Set.of("email"), NOW.plusSeconds(300)));
        var email = mock(EmailMfaService.class);
        AuthenticationSuccessHandler delegate = (request, response, authentication) -> {
            throw new AssertionError("password login must wait for MFA");
        };
        var handler = handler(
                delegate,
                user -> new MfaPolicy(true, Set.of("email"), Duration.ofMinutes(5)),
                transactions,
                email,
                failureHandler());
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(request, response, authenticatedUser());

        verify(email).beginLogin("alice", "transaction", NOW.plusSeconds(300));
        assertThat(response.getStatus()).isEqualTo(HttpStatus.ACCEPTED.value());
        assertThat(response.getContentAsString()).contains("transaction", "email");
        assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
    }

    @Test
    void completesMfaAuthenticationAndAddsFactorToSessionDetails() throws Exception {
        AtomicReference<Authentication> delegated = new AtomicReference<>();
        MfaLoginTransaction transaction =
                new MfaLoginTransaction("alice", Set.of("totp"), Set.of("pwd"), NOW, NOW.plusSeconds(300), CLIENT);
        var handler = handler(
                (request, response, authentication) -> delegated.set(authentication),
                user -> enabledPolicy(),
                null,
                null,
                failureHandler());
        UsernamePasswordAuthenticationToken authentication = (UsernamePasswordAuthenticationToken) authenticatedUser();
        authentication.setDetails(new MfaLoginCompletion(transaction, "totp", NOW.plusSeconds(20)));

        handler.onAuthenticationSuccess(new MockHttpServletRequest(), new MockHttpServletResponse(), authentication);

        assertThat(delegated.get().getDetails())
                .isInstanceOf(io.zhijun.security.core.UserSessionAuthenticationDetails.class);
        var details = (io.zhijun.security.core.UserSessionAuthenticationDetails)
                delegated.get().getDetails();
        assertThat(details.authenticationMethods()).contains("pwd", "totp");
        assertThat(details.clientInfo()).isEqualTo(CLIENT);
        assertThat(details.authenticatedAt()).isEqualTo(NOW.plusSeconds(20));
    }

    private static MfaAwareLoginSuccessHandler handler(
            AuthenticationSuccessHandler delegate,
            io.zhijun.security.core.MfaPolicyProvider policies,
            MfaLoginTransactionService transactions,
            EmailMfaService email,
            AuthenticationFailureHandler failures) {
        return new MfaAwareLoginSuccessHandler(
                delegate,
                policies,
                transactions,
                email,
                failures,
                request -> CLIENT,
                JsonMapper.builder().build(),
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private static MfaPolicy enabledPolicy() {
        return new MfaPolicy(true, Set.of("totp"), Duration.ofMinutes(5));
    }

    private static Authentication authenticatedUser() {
        return UsernamePasswordAuthenticationToken.authenticated(
                USER, null, AuthorityUtils.createAuthorityList("ROLE_USER"));
    }

    private static AuthenticationFailureHandler failureHandler() {
        return (request, response, exception) -> response.setStatus(HttpStatus.UNAUTHORIZED.value());
    }
}

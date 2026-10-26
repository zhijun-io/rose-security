package io.zhijun.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.zhijun.security.core.MfaFactorAuthenticationToken;
import io.zhijun.security.core.MfaLoginTransaction;
import io.zhijun.security.core.MfaPolicy;
import io.zhijun.security.core.TotpCredential;
import io.zhijun.security.core.UserSessionClientInfo;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import tools.jackson.databind.json.JsonMapper;

class MfaAuthenticationTests {

    private static final Instant NOW = Instant.parse("2026-10-26T00:00:00Z");
    private static final UserDetails USER = User.withUsername("user@example.test")
            .password("unused")
            .authorities("ROLE_USER")
            .build();

    @Test
    void factorTokenAndPolicyKeepTheirSecurityInvariants() {
        var token = MfaFactorAuthenticationToken.unauthenticated("user@example.test", "totp", "123456", "pending");
        assertThat(token.getPrincipal()).isEqualTo("user@example.test");
        assertThat(token.getCredentials()).isEqualTo("123456");
        assertThat(token.transactionToken()).isEqualTo("pending");
        assertThat(token.toString()).doesNotContain("user@example.test", "123456", "pending");
        assertThatThrownBy(() -> token.setAuthenticated(true)).isInstanceOf(IllegalArgumentException.class);
        token.eraseCredentials();
        assertThat(token.getCredentials()).isNull();

        var methods = new java.util.LinkedHashSet<>(Set.of("totp"));
        var policy = new MfaPolicy(true, methods, Duration.ofMinutes(5));
        methods.add("email");
        assertThat(policy.methods()).containsExactly("totp");
        assertThatThrownBy(() -> new MfaPolicy(true, Set.of("TOTP"), Duration.ofMinutes(5)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new MfaPolicy(false, Set.of(), Duration.ZERO))
                .isInstanceOf(IllegalArgumentException.class);

        var transaction = new MfaLoginTransaction(
                "user@example.test",
                Set.of("totp"),
                Set.of("pwd"),
                NOW,
                NOW.plusSeconds(60),
                new UserSessionClientInfo("192.0.2.10", "browser"));
        assertThat(transaction.toString()).doesNotContain("user@example.test", "192.0.2.10");
        assertThat(new TotpCredential("secret", -1).toString()).doesNotContain("secret");
    }

    @Test
    void converterReadsRequiredFieldsAndRejectsMalformedRequests() {
        var converter = new JsonMfaVerificationAuthenticationConverter(
                JsonMapper.builder().build());
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContent("{\"transaction_token\":\"pending\",\"method\":\"totp\",\"proof\":\"123456\"}"
                .getBytes(java.nio.charset.StandardCharsets.UTF_8));

        Authentication converted = converter.convert(request);
        assertThat(converted).isInstanceOf(MfaVerificationAuthenticationToken.class);
        var token = (MfaVerificationAuthenticationToken) converted;
        assertThat(token.transactionToken()).isEqualTo("pending");
        assertThat(token.method()).isEqualTo("totp");
        assertThat(token.getCredentials()).isEqualTo("123456");
        assertThat(token.toString()).doesNotContain("pending", "123456");
        assertThatThrownBy(() -> token.setAuthenticated(true)).isInstanceOf(IllegalArgumentException.class);
        token.eraseCredentials();
        assertThat(token.getCredentials()).isNull();

        MockHttpServletRequest invalid = new MockHttpServletRequest();
        invalid.setContent("{\"transaction_token\":\"pending\",\"method\":\"totp\",\"proof\":\" \"}"
                .getBytes(java.nio.charset.StandardCharsets.UTF_8));
        assertThatThrownBy(() -> converter.convert(invalid)).isInstanceOf(BadCredentialsException.class);
    }

    @Test
    void providersAuthenticateOnlyTheirOwnFactorAndCheckCurrentUser() {
        TotpMfaService totp = mock(TotpMfaService.class);
        EmailMfaService email = mock(EmailMfaService.class);
        WebAuthnMfaService webAuthn = mock(WebAuthnMfaService.class);
        when(totp.verify(USER.getUsername(), "123456")).thenReturn(true);
        when(email.verifyLogin(USER.getUsername(), "pending", "123456", NOW)).thenReturn(true);
        when(webAuthn.verifyLogin(USER.getUsername(), "pending", "proof", NOW)).thenReturn(true);
        UserDetailsService users = username -> USER;
        var clock = Clock.fixed(NOW, ZoneOffset.UTC);
        var totpProvider = new TotpAuthenticationProvider(totp, users);
        var emailProvider = new EmailMfaAuthenticationProvider(email, users, clock);
        var webAuthnProvider = new WebAuthnMfaAuthenticationProvider(webAuthn, users, clock);

        assertThat(totpProvider
                        .authenticate(
                                MfaFactorAuthenticationToken.unauthenticated(USER.getUsername(), "totp", "123456"))
                        .getPrincipal())
                .isEqualTo(USER);
        assertThat(emailProvider
                        .authenticate(MfaFactorAuthenticationToken.unauthenticated(
                                USER.getUsername(), "email", "123456", "pending"))
                        .getPrincipal())
                .isEqualTo(USER);
        assertThat(webAuthnProvider
                        .authenticate(MfaFactorAuthenticationToken.unauthenticated(
                                USER.getUsername(), "webauthn", "proof", "pending"))
                        .getPrincipal())
                .isEqualTo(USER);
        assertThat(totpProvider.authenticate(UsernamePasswordAuthenticationToken.unauthenticated("user", "secret")))
                .isNull();
        assertThat(emailProvider.authenticate(
                        MfaFactorAuthenticationToken.unauthenticated(USER.getUsername(), "totp", "123456")))
                .isNull();
        assertThatThrownBy(() -> webAuthnProvider.authenticate(
                        MfaFactorAuthenticationToken.unauthenticated(USER.getUsername(), "webauthn", "proof")))
                .isInstanceOf(BadCredentialsException.class);
        assertThat(totpProvider.supports(MfaFactorAuthenticationToken.class)).isTrue();
        assertThat(emailProvider.supports(MfaFactorAuthenticationToken.class)).isTrue();
        assertThat(webAuthnProvider.supports(MfaFactorAuthenticationToken.class))
                .isTrue();
    }

    @Test
    void invalidProofsDoNotAuthenticate() {
        TotpMfaService totp = mock(TotpMfaService.class);
        EmailMfaService email = mock(EmailMfaService.class);
        WebAuthnMfaService webAuthn = mock(WebAuthnMfaService.class);
        when(totp.verify(USER.getUsername(), "000000")).thenReturn(false);
        when(email.verifyLogin(USER.getUsername(), "pending", "000000", NOW)).thenReturn(false);
        when(webAuthn.verifyLogin(USER.getUsername(), "pending", "bad", NOW)).thenReturn(false);
        UserDetailsService users = username -> USER;

        assertThatThrownBy(() -> new TotpAuthenticationProvider(totp, users)
                        .authenticate(
                                MfaFactorAuthenticationToken.unauthenticated(USER.getUsername(), "totp", "000000")))
                .isInstanceOf(BadCredentialsException.class);
        assertThatThrownBy(() -> new EmailMfaAuthenticationProvider(email, users, Clock.fixed(NOW, ZoneOffset.UTC))
                        .authenticate(MfaFactorAuthenticationToken.unauthenticated(
                                USER.getUsername(), "email", "000000", "pending")))
                .isInstanceOf(BadCredentialsException.class);
        assertThatThrownBy(
                        () -> new WebAuthnMfaAuthenticationProvider(webAuthn, users, Clock.fixed(NOW, ZoneOffset.UTC))
                                .authenticate(MfaFactorAuthenticationToken.unauthenticated(
                                        USER.getUsername(), "webauthn", "bad", "pending")))
                .isInstanceOf(BadCredentialsException.class);
    }
}

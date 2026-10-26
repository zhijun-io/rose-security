package io.zhijun.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import tools.jackson.databind.json.JsonMapper;

class MfaManagementFilterTests {

    private static final String USERNAME = "user@example.test";
    private static final Instant NOW = Instant.parse("2026-10-26T00:00:00Z");

    private TotpMfaService totp;
    private EmailMfaService email;
    private WebAuthnMfaService webAuthn;
    private MfaLoginTransactionService transactions;
    private MfaManagementFilter filter;

    @BeforeEach
    void setUp() {
        totp = mock(TotpMfaService.class);
        email = mock(EmailMfaService.class);
        webAuthn = mock(WebAuthnMfaService.class);
        transactions = mock(MfaLoginTransactionService.class);
        var properties = new MfaProperties.Mfa(
                true,
                Set.of("totp", "email", "webauthn"),
                Duration.ofMinutes(5),
                5,
                "Rose",
                "example.test",
                Set.of("https://example.test"));
        AuthenticationFailureHandler failures = (request, response, exception) ->
                response.setStatus(exception instanceof BadCredentialsException ? 401 : 503);
        filter = new MfaManagementFilter(
                "/api/me/mfa/",
                "/api/auth/mfa/webauthn/options",
                totp,
                email,
                properties,
                "Rose",
                JsonMapper.builder().build(),
                failures,
                Clock.fixed(NOW, ZoneOffset.UTC),
                webAuthn,
                transactions);
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt(), List.of()));
        assertThat(SecurityContextHolder.getContext().getAuthentication().isAuthenticated())
                .isTrue();
        assertThat(SecurityContextHolder.getContext().getAuthentication().getPrincipal())
                .isInstanceOf(Jwt.class);
    }

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void statusAndTotpManagementUseAuthenticatedUser() throws Exception {
        when(totp.isEnrolled(USERNAME)).thenReturn(true);
        when(email.isEnabled(USERNAME)).thenReturn(false);
        when(webAuthn.isEnrolled(USERNAME)).thenReturn(true);
        when(webAuthn.credentials(USERNAME)).thenReturn(List.of(new WebAuthnMfaService.Credential("id", "Laptop")));
        when(totp.beginEnrollment(USERNAME, "Rose"))
                .thenReturn(new TotpMfaService.Enrollment("secret", "otpauth://uri", NOW.plusSeconds(60)));
        when(totp.confirmEnrollment(USERNAME, "123456")).thenReturn(true);
        when(totp.verify(USERNAME, "123456")).thenReturn(true);

        var status = perform("GET", "/api/me/mfa", "");
        assertThat(status.getStatus()).isEqualTo(200);
        assertThat(status.getContentAsString()).contains("totpEnrolled", "webauthnEnrolled", "Laptop");
        assertThat(status.getHeader("Cache-Control")).isEqualTo("no-store");

        var enrollment = perform("POST", "/api/me/mfa/totp", "{}");
        assertThat(enrollment.getStatus()).isEqualTo(200);
        assertThat(enrollment.getContentAsString()).contains("secret", "otpauth_uri");

        assertThat(perform("POST", "/api/me/mfa/totp/verify", "{\"code\":\"123456\"}")
                        .getStatus())
                .isEqualTo(204);
        assertThat(perform("DELETE", "/api/me/mfa/totp", "{\"code\":\"123456\"}")
                        .getStatus())
                .isEqualTo(204);
        verify(totp).remove(USERNAME);
    }

    @Test
    void emailEnrollmentLoginAndRemovalDispatchToEmailService() throws Exception {
        var challenge = new EmailMfaService.Challenge("email-token", NOW.plusSeconds(60));
        when(email.beginEnrollment(USERNAME, Duration.ofMinutes(5), NOW)).thenReturn(challenge);
        when(email.beginRemoval(USERNAME, Duration.ofMinutes(5), NOW)).thenReturn(challenge);
        when(email.isEnabled(USERNAME)).thenReturn(true);
        when(email.confirmEnrollment(USERNAME, "email-token", "123456", NOW, 5)).thenReturn(true);
        when(email.confirmRemoval(USERNAME, "email-token", "123456", NOW, 5)).thenReturn(true);

        var enrollment = perform("POST", "/api/me/mfa/email", "{}");
        assertThat(enrollment.getStatus()).isEqualTo(200);
        assertThat(enrollment.getContentAsString()).contains("challenge_token");
        assertThat(perform(
                                "POST",
                                "/api/me/mfa/email/verify",
                                "{\"challenge_token\":\"email-token\",\"code\":\"123456\"}")
                        .getStatus())
                .isEqualTo(204);
        assertThat(perform("DELETE", "/api/me/mfa/email", "").getStatus()).isEqualTo(202);
        assertThat(perform(
                                "POST",
                                "/api/me/mfa/email/remove/verify",
                                "{\"challenge_token\":\"email-token\",\"code\":\"123456\"}")
                        .getStatus())
                .isEqualTo(204);
    }

    @Test
    void webAuthnOptionsAndManagementDispatchUseConfiguredServices() throws Exception {
        var challenge = new WebAuthnMfaService.StartedChallenge(
                "challenge", java.util.Map.of("publicKey", true), NOW.plusSeconds(60));
        when(transactions.usernameFor("login-token", "webauthn", NOW)).thenReturn(USERNAME);
        when(webAuthn.beginLogin(USERNAME, "login-token", NOW)).thenReturn(challenge);
        when(webAuthn.beginRegistration(USERNAME, NOW)).thenReturn(challenge);
        when(webAuthn.beginRemoval(USERNAME, "credential-id", NOW)).thenReturn(challenge);

        var loginOptions = perform("POST", "/api/auth/mfa/webauthn/options", "{\"transaction_token\":\"login-token\"}");
        assertThat(loginOptions.getStatus()).isEqualTo(200);
        assertThat(loginOptions.getContentAsString()).contains("challenge");
        verify(transactions).usernameFor("login-token", "webauthn", NOW);

        assertThat(perform("POST", "/api/me/mfa/webauthn/register/options", "{}")
                        .getStatus())
                .isEqualTo(200);
        assertThat(perform(
                                "POST",
                                "/api/me/mfa/webauthn/register",
                                "{\"challenge_token\":\"registration-token\",\"publicKey\":{\"label\":\"Laptop\"}}")
                        .getStatus())
                .isEqualTo(204);
        verify(webAuthn)
                .completeRegistration(
                        eq(USERNAME),
                        eq("registration-token"),
                        any(WebAuthnMfaService.RegistrationProof.class),
                        eq(NOW));

        assertThat(perform("POST", "/api/me/mfa/webauthn/remove/options", "{\"credential_id\":\"credential-id\"}")
                        .getStatus())
                .isEqualTo(200);
        assertThat(perform(
                                "POST",
                                "/api/me/mfa/webauthn/remove",
                                "{\"challenge_token\":\"remove-token\",\"credential_id\":\"credential-id\"}")
                        .getStatus())
                .isEqualTo(204);
        verify(webAuthn).completeRemoval(eq(USERNAME), eq("remove-token"), eq("credential-id"), eq(null), eq(NOW));
    }

    @Test
    void malformedProofUnauthenticatedRequestAndUnknownMethodFailClosed() throws Exception {
        assertThat(perform("POST", "/api/me/mfa/totp/verify", "{\"code\":\"bad\"}")
                        .getStatus())
                .isEqualTo(401);
        SecurityContextHolder.clearContext();
        assertThat(perform("GET", "/api/me/mfa", "").getStatus()).isEqualTo(401);
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt(), List.of()));
        assertThat(perform("PUT", "/api/me/mfa", "").getStatus()).isEqualTo(405);
        assertThat(perform("POST", "/api/me/mfa/webauthn/unknown", "{}").getStatus())
                .isEqualTo(405);
        assertThat(perform("GET", "/unmanaged", "").getStatus()).isEqualTo(200);
    }

    @Test
    void webAuthnLoginOptionsRequireATransactionAndFailuresAreMapped() throws Exception {
        assertThat(perform("POST", "/api/auth/mfa/webauthn/options", "{}").getStatus())
                .isEqualTo(401);
        when(transactions.usernameFor("login-token", "webauthn", NOW))
                .thenThrow(new BadCredentialsException("Authentication failed"));
        assertThat(perform("POST", "/api/auth/mfa/webauthn/options", "{\"transaction_token\":\"login-token\"}")
                        .getStatus())
                .isEqualTo(401);
    }

    @Test
    void invalidEnrollmentProofsAndDisabledRemovalFailClosed() throws Exception {
        when(totp.confirmEnrollment(USERNAME, "000000")).thenReturn(false);
        when(email.isEnabled(USERNAME)).thenReturn(false);

        assertThat(perform("POST", "/api/me/mfa/totp/verify", "{\"code\":\"000000\"}")
                        .getStatus())
                .isEqualTo(401);
        assertThat(perform("DELETE", "/api/me/mfa/email", "").getStatus()).isEqualTo(401);
        assertThat(perform("POST", "/api/me/mfa/webauthn/register", "{}").getStatus())
                .isEqualTo(401);
        assertThat(perform("POST", "/api/auth/mfa/webauthn/options", "not-json").getStatus())
                .isEqualTo(401);
    }

    private MockHttpServletResponse perform(String method, String path, String content) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(method, path);
        request.setServletPath(path);
        request.setContent(content.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());
        return response;
    }

    private static Jwt jwt() {
        return Jwt.withTokenValue("access-token")
                .header("alg", "none")
                .subject(USERNAME)
                .issuedAt(NOW.minusSeconds(1))
                .expiresAt(NOW.plusSeconds(60))
                .build();
    }
}

package io.zhijun.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.zhijun.security.core.IssuedSessionTokens;
import io.zhijun.security.core.UserSessionClientInfo;
import io.zhijun.security.core.UserSessionService;
import io.zhijun.security.core.UserSessionView;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import tools.jackson.databind.json.JsonMapper;

class AuthSecurityConfigurerTests {

    private static final Instant NOW = Instant.parse("2026-10-21T12:00:00Z");
    private static final org.springframework.security.core.userdetails.UserDetails USER = User.withUsername(
                    "user@example.test")
            .password("unused")
            .authorities("ROLE_USER")
            .build();

    @Test
    void completedLoginCreatesSessionAndReturnsNoStoreTokenResponse() throws Exception {
        AtomicInteger creates = new AtomicInteger();
        TokenAuthenticationSuccessHandler handler = successHandler(new StubUserSessionService(creates));
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(
                new MockHttpServletRequest(), response, new MockFilterChain(), authenticatedUser());

        assertThat(creates).hasValue(1);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
        assertThat(response.getContentAsString()).contains("access_token", "refresh_token", "session-1");
        assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
        assertThat(response.getHeader("Pragma")).isEqualTo("no-cache");
    }

    @Test
    void remoteLoginHandlerRunsAfterTokenResponseIsWritten() throws Exception {
        AtomicInteger notifications = new AtomicInteger();
        MockHttpServletResponse response = new MockHttpServletResponse();
        TokenAuthenticationSuccessHandler handler = new TokenAuthenticationSuccessHandler(
                new StubUserSessionService(new AtomicInteger()),
                new DefaultUserSessionClientInfoDetailsSource(),
                failureHandler(),
                JsonMapper.builder().build(),
                Clock.fixed(NOW, ZoneOffset.UTC),
                (username, clientInfo, sessionId) -> {
                    assertThat(response.getContentAsByteArray()).isNotEmpty();
                    assertThat(username).isEqualTo("user@example.test");
                    assertThat(clientInfo.clientIp()).isNotBlank();
                    assertThat(sessionId).isEqualTo("session-1");
                    notifications.incrementAndGet();
                },
                true);

        handler.onAuthenticationSuccess(
                new MockHttpServletRequest(), response, new MockFilterChain(), authenticatedUser());

        assertThat(notifications).hasValue(1);
    }

    @Test
    void remoteLoginHandlerFailureDoesNotReplaceSuccessfulLoginResponse() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        TokenAuthenticationSuccessHandler handler = new TokenAuthenticationSuccessHandler(
                new StubUserSessionService(new AtomicInteger()),
                new DefaultUserSessionClientInfoDetailsSource(),
                failureHandler(),
                JsonMapper.builder().build(),
                Clock.fixed(NOW, ZoneOffset.UTC),
                (username, clientInfo, sessionId) -> {
                    throw new IllegalStateException("notification unavailable");
                },
                true);

        handler.onAuthenticationSuccess(
                new MockHttpServletRequest(), response, new MockFilterChain(), authenticatedUser());

        assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
        assertThat(response.getContentAsString()).contains("access_token", "refresh_token");
    }

    @Test
    void refreshSuccessHandlerWritesRotatedTokens() throws Exception {
        RefreshTokenAuthenticationSuccessHandler handler = new RefreshTokenAuthenticationSuccessHandler(
                failureHandler(), JsonMapper.builder().build(), Clock.fixed(NOW, ZoneOffset.UTC));
        MockHttpServletResponse response = new MockHttpServletResponse();
        IssuedSessionTokens tokens = new IssuedSessionTokens(
                "rotated-access", NOW.plusSeconds(600), "rotated-refresh", NOW.plusSeconds(1200), "session-1");

        handler.onAuthenticationSuccess(
                new MockHttpServletRequest(),
                response,
                new MockFilterChain(),
                RefreshRequestAuthenticationToken.authenticated(tokens));

        assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
        assertThat(response.getContentAsString()).contains("rotated-access", "rotated-refresh", "session-1");
        assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
        assertThat(response.getHeader("Pragma")).isEqualTo("no-cache");
    }

    @Test
    void refreshSuccessHandlerUsesSpringAuthenticationFailureHandling() throws Exception {
        RefreshTokenAuthenticationSuccessHandler handler = new RefreshTokenAuthenticationSuccessHandler(
                failureHandler(), JsonMapper.builder().build(), Clock.fixed(NOW, ZoneOffset.UTC));
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertThatThrownBy(() -> handler.onAuthenticationSuccess(
                        new MockHttpServletRequest(), response, new MockFilterChain(), authenticatedUser()))
                .isInstanceOf(AuthenticationServiceException.class);

        assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
        assertThat(response.getContentAsString()).isEmpty();
    }

    @Test
    void tokenResponseOmitsRefreshFieldsWhenRefreshIsDisabled() throws Exception {
        String json = JsonMapper.builder()
                .build()
                .writeValueAsString(
                        new AuthenticationTokenResponse("access-value", "Bearer", 600, null, null, "session-1"));

        assertThat(json).contains("access_token", "session_id");
        assertThat(json).doesNotContain("refresh_token", "refresh_expires_at");
    }

    private static TokenAuthenticationSuccessHandler successHandler(UserSessionService userSessionService) {
        return new TokenAuthenticationSuccessHandler(
                userSessionService,
                new DefaultUserSessionClientInfoDetailsSource(),
                failureHandler(),
                JsonMapper.builder().build(),
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private static org.springframework.security.web.authentication.AuthenticationFailureHandler failureHandler() {
        return new org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler(
                new org.springframework.security.web.authentication.HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));
    }

    private static Authentication authenticatedUser() {
        return UsernamePasswordAuthenticationToken.authenticated(
                USER, "secret-password", AuthorityUtils.createAuthorityList("ROLE_USER"));
    }

    private static final class StubUserSessionService implements UserSessionService {

        private final AtomicInteger creates;

        private StubUserSessionService(AtomicInteger creates) {
            this.creates = creates;
        }

        @Override
        public IssuedSessionTokens create(
                org.springframework.security.core.userdetails.UserDetails principal,
                Collection<String> authenticationMethods,
                Instant authenticatedAt,
                UserSessionClientInfo clientInfo) {
            creates.incrementAndGet();
            return new IssuedSessionTokens(
                    "access-value", NOW.plusSeconds(600), "refresh-value", NOW.plusSeconds(1200), "session-1");
        }

        @Override
        public IssuedSessionTokens refresh(String refreshToken) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean revoke(String username, String sessionId) {
            return false;
        }

        @Override
        public int revokeAll(String username) {
            return 0;
        }

        @Override
        public List<UserSessionView> findActiveSessions(String username) {
            return List.of();
        }
    }
}

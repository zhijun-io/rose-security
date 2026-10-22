package io.zhijun.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import io.zhijun.security.core.IssuedSessionTokens;
import io.zhijun.security.core.UserSessionClientInfo;
import io.zhijun.security.core.UserSessionService;
import io.zhijun.security.core.UserSessionView;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;

class UserSessionLogoutHandlerTests {

    private static final Instant NOW = Instant.parse("2026-10-21T12:00:00Z");
    private static final String USERNAME = "person@example.test";

    @Test
    void revokesTheSessionClaimedByBearerToken() {
        AtomicReference<String> revokedUsername = new AtomicReference<>();
        AtomicReference<String> revokedSessionId = new AtomicReference<>();
        UserSessionLogoutHandler handler = handler(
                new RecordingUserSessionService() {
                    @Override
                    public boolean revoke(String username, String sessionId) {
                        revokedUsername.set(username);
                        revokedSessionId.set(sessionId);
                        return true;
                    }
                },
                jwtDecoder("session-1"),
                "/api/auth/logout-all");
        MockHttpServletRequest request = request("/api/auth/logout", "Bearer access-token");

        handler.logout(request, new MockHttpServletResponse(), null);

        assertThat(revokedUsername).hasValue(USERNAME);
        assertThat(revokedSessionId).hasValue("session-1");
        assertThat(request.getAttribute(UserSessionLogoutHandler.FAILURE_ATTRIBUTE))
                .isNull();
    }

    @Test
    void revokesAllSessionsWhenConfiguredLogoutAllPathIsRequested() {
        AtomicReference<String> revokedUsername = new AtomicReference<>();
        UserSessionLogoutHandler handler = handler(
                new RecordingUserSessionService() {
                    @Override
                    public int revokeAll(String username) {
                        revokedUsername.set(username);
                        return 3;
                    }
                },
                jwtDecoder(null),
                "/api/auth/logout-all");
        MockHttpServletRequest request = request("/api/auth/logout-all", "Bearer access-token");

        handler.logout(request, new MockHttpServletResponse(), null);

        assertThat(revokedUsername).hasValue(USERNAME);
        assertThat(request.getAttribute(UserSessionLogoutHandler.FAILURE_ATTRIBUTE))
                .isNull();
    }

    @Test
    void rejectsMissingBearerTokenWithoutCallingSessionService() {
        UserSessionLogoutHandler handler = handler(new RecordingUserSessionService(), jwtDecoder("session-1"), null);
        MockHttpServletRequest request = request("/api/auth/logout", null);

        handler.logout(request, new MockHttpServletResponse(), null);

        assertThat(request.getAttribute(UserSessionLogoutHandler.FAILURE_ATTRIBUTE))
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void rejectsTokenWithoutSessionIdForSingleSessionLogout() {
        UserSessionLogoutHandler handler = handler(new RecordingUserSessionService(), jwtDecoder(null), null);
        MockHttpServletRequest request = request("/api/auth/logout", "Bearer access-token");

        handler.logout(request, new MockHttpServletResponse(), null);

        assertThat(request.getAttribute(UserSessionLogoutHandler.FAILURE_ATTRIBUTE))
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void reportsServiceFailureAsUnavailable() {
        UserSessionLogoutHandler handler = handler(
                new RecordingUserSessionService() {
                    @Override
                    public boolean revoke(String username, String sessionId) {
                        throw new IllegalStateException("storage unavailable");
                    }
                },
                jwtDecoder("session-1"),
                null);
        MockHttpServletRequest request = request("/api/auth/logout", "Bearer access-token");

        handler.logout(request, new MockHttpServletResponse(), null);

        assertThat(request.getAttribute(UserSessionLogoutHandler.FAILURE_ATTRIBUTE))
                .isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
    }

    private static UserSessionLogoutHandler handler(
            UserSessionService service,
            org.springframework.security.oauth2.jwt.JwtDecoder decoder,
            String logoutAllPath) {
        return new UserSessionLogoutHandler(service, decoder, logoutAllPath);
    }

    private static org.springframework.security.oauth2.jwt.JwtDecoder jwtDecoder(String sessionId) {
        return token -> {
            Jwt.Builder builder = Jwt.withTokenValue(token)
                    .header("alg", "RS256")
                    .subject(USERNAME)
                    .issuedAt(NOW.minusSeconds(60))
                    .expiresAt(NOW.plusSeconds(60));
            if (sessionId != null) {
                builder.claim("sid", sessionId);
            }
            return builder.build();
        };
    }

    private static MockHttpServletRequest request(String path, String authorization) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath(path);
        if (authorization != null) {
            request.addHeader("Authorization", authorization);
        }
        return request;
    }

    private static class RecordingUserSessionService implements UserSessionService {

        @Override
        public IssuedSessionTokens create(
                UserDetails principal,
                Collection<String> authenticationMethods,
                Instant authenticatedAt,
                UserSessionClientInfo clientInfo) {
            throw new UnsupportedOperationException();
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
        public List<UserSessionView> findActiveSessions(String username) {
            throw new UnsupportedOperationException();
        }
    }
}

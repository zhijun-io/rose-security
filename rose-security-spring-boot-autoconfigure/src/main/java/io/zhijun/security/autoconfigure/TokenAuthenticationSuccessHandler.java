package io.zhijun.security.autoconfigure;

import io.zhijun.security.core.IssuedSessionTokens;
import io.zhijun.security.core.UserSessionClientInfo;
import io.zhijun.security.core.UserSessionException;
import io.zhijun.security.core.UserSessionService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Clock;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import tools.jackson.databind.json.JsonMapper;

/** Creates a token session after successful login authentication. */
public class TokenAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger logger = LoggerFactory.getLogger(TokenAuthenticationSuccessHandler.class);

    private final UserSessionService userSessionService;
    private final AuthenticationDetailsSource<HttpServletRequest, UserSessionClientInfo> clientInfoSource;
    private final AuthenticationFailureHandler failureHandler;
    private final JsonMapper jsonMapper;
    private final Clock clock;
    private final RemoteLoginHandler remoteLoginHandler;
    private final boolean remoteLoginEnabled;

    public TokenAuthenticationSuccessHandler(
            UserSessionService userSessionService,
            AuthenticationDetailsSource<HttpServletRequest, UserSessionClientInfo> clientInfoSource,
            AuthenticationFailureHandler failureHandler,
            JsonMapper jsonMapper,
            Clock clock) {
        this(userSessionService, clientInfoSource, failureHandler, jsonMapper, clock, null, false);
    }

    public TokenAuthenticationSuccessHandler(
            UserSessionService userSessionService,
            AuthenticationDetailsSource<HttpServletRequest, UserSessionClientInfo> clientInfoSource,
            AuthenticationFailureHandler failureHandler,
            JsonMapper jsonMapper,
            Clock clock,
            RemoteLoginHandler remoteLoginHandler,
            boolean remoteLoginEnabled) {
        this.userSessionService = userSessionService;
        this.clientInfoSource = clientInfoSource;
        this.failureHandler = failureHandler;
        this.jsonMapper = jsonMapper;
        this.clock = clock;
        this.remoteLoginHandler = remoteLoginHandler;
        this.remoteLoginEnabled = remoteLoginEnabled;
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {
        IssuedSessionTokens tokens = tokensFor(request, response, authentication);
        if (tokens != null) {
            writeTokens(response, tokens);
            notifyRemoteLogin(request, authentication, tokens);
        }
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication)
            throws IOException, ServletException {
        onAuthenticationSuccess(request, response, authentication);
    }

    protected IssuedSessionTokens tokensFor(
            HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {
        if (!(authentication.getPrincipal() instanceof UserDetails principal)) {
            fail(request, response, new AuthenticationServiceException("Authentication could not be completed"));
            return null;
        }
        try {
            if (authentication.getDetails() instanceof MfaLoginCompletion completion) {
                java.util.Set<String> methods =
                        new java.util.HashSet<>(completion.transaction().authenticationMethods());
                methods.add(completion.method());
                return userSessionService.create(
                        principal,
                        methods,
                        completion.authenticatedAt(),
                        completion.transaction().clientInfo());
            }
            return userSessionService.create(
                    principal, Set.of("pwd"), clock.instant(), clientInfoSource.buildDetails(request));
        } catch (RuntimeException exception) {
            AuthenticationException failure = exception instanceof UserSessionException sessionException
                            && sessionException.reason() == UserSessionException.Reason.SESSION_LIMIT_REACHED
                    ? new SessionAuthenticationException("Authentication failed")
                    : new AuthenticationServiceException("Authentication could not be completed", exception);
            fail(request, response, failure);
            return null;
        }
    }

    protected void writeTokens(HttpServletResponse response, IssuedSessionTokens tokens) throws IOException {
        TokenResponseWriter.write(response, tokens, jsonMapper, clock);
    }

    private void notifyRemoteLogin(
            HttpServletRequest request, Authentication authentication, IssuedSessionTokens tokens) {
        if (!remoteLoginEnabled
                || remoteLoginHandler == null
                || !(authentication.getPrincipal() instanceof UserDetails user)) {
            return;
        }
        try {
            UserSessionClientInfo clientInfo = authentication.getDetails() instanceof MfaLoginCompletion completion
                    ? completion.transaction().clientInfo()
                    : clientInfoSource.buildDetails(request);
            remoteLoginHandler.handle(user.getUsername(), clientInfo, tokens.sessionId());
        } catch (RuntimeException exception) {
            logger.warn("Remote-login handling failed; the authenticated response was already written");
        }
    }

    protected void fail(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
            throws IOException, ServletException {
        failureHandler.onAuthenticationFailure(request, response, exception);
    }
}

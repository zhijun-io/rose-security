package io.zhijun.security.autoconfigure;

import io.zhijun.security.core.IssuedSessionTokens;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Clock;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import tools.jackson.databind.json.JsonMapper;

/** Writes the tokens returned by the refresh authentication flow. */
public class RefreshTokenAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final AuthenticationFailureHandler failureHandler;
    private final JsonMapper jsonMapper;
    private final Clock clock;

    public RefreshTokenAuthenticationSuccessHandler(
            AuthenticationFailureHandler failureHandler, JsonMapper jsonMapper, Clock clock) {
        this.failureHandler = failureHandler;
        this.jsonMapper = jsonMapper;
        this.clock = clock;
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {
        IssuedSessionTokens tokens = tokensFor(request, response, authentication);
        if (tokens != null) {
            writeTokens(response, tokens);
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
        if (authentication instanceof RefreshRequestAuthenticationToken refresh
                && refresh.isAuthenticated()
                && refresh.tokens() != null) {
            return refresh.tokens();
        }
        fail(request, response, new AuthenticationServiceException("Authentication could not be completed"));
        return null;
    }

    protected void writeTokens(HttpServletResponse response, IssuedSessionTokens tokens) throws IOException {
        TokenResponseWriter.write(response, tokens, jsonMapper, clock);
    }

    protected void fail(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
            throws IOException, ServletException {
        failureHandler.onAuthenticationFailure(request, response, exception);
    }
}

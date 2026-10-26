package io.zhijun.security.autoconfigure;

import io.zhijun.security.core.MfaPolicy;
import io.zhijun.security.core.MfaPolicyProvider;
import io.zhijun.security.core.UserSessionAuthenticationDetails;
import io.zhijun.security.core.UserSessionClientInfo;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Clock;
import java.util.Collection;
import java.util.Set;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import tools.jackson.databind.json.JsonMapper;

/** Starts a pending MFA transaction in place of issuing a full session token. */
public class MfaAwareLoginSuccessHandler implements AuthenticationSuccessHandler {

    private final AuthenticationSuccessHandler delegate;
    private final MfaPolicyProvider policyProvider;
    private final MfaLoginTransactionService transactionService;
    private final EmailMfaService emailMfaService;
    private final AuthenticationFailureHandler failureHandler;
    private final org.springframework.security.authentication.AuthenticationDetailsSource<
                    HttpServletRequest, UserSessionClientInfo>
            clientInfoSource;
    private final JsonMapper jsonMapper;
    private final Clock clock;

    public MfaAwareLoginSuccessHandler(
            AuthenticationSuccessHandler delegate,
            MfaPolicyProvider policyProvider,
            MfaLoginTransactionService transactionService,
            EmailMfaService emailMfaService,
            AuthenticationFailureHandler failureHandler,
            org.springframework.security.authentication.AuthenticationDetailsSource<
                            HttpServletRequest, UserSessionClientInfo>
                    clientInfoSource,
            JsonMapper jsonMapper,
            Clock clock) {
        this.delegate = delegate;
        this.policyProvider = policyProvider;
        this.transactionService = transactionService;
        this.emailMfaService = emailMfaService;
        this.failureHandler = failureHandler;
        this.clientInfoSource = clientInfoSource;
        this.jsonMapper = jsonMapper;
        this.clock = clock;
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {
        if (authentication.getDetails() instanceof MfaLoginCompletion) {
            MfaLoginCompletion completion = (MfaLoginCompletion) authentication.getDetails();
            var transaction = completion.transaction();
            Authentication completed = UsernamePasswordAuthenticationToken.authenticated(
                    authentication.getPrincipal(), null, authentication.getAuthorities());
            ((UsernamePasswordAuthenticationToken) completed)
                    .setDetails(new UserSessionAuthenticationDetails(
                            union(transaction.authenticationMethods(), completion.method()),
                            completion.authenticatedAt(),
                            transaction.clientInfo()));
            delegate.onAuthenticationSuccess(request, response, completed);
            return;
        }
        if (!(authentication.getPrincipal() instanceof UserDetails user)) {
            delegate.onAuthenticationSuccess(request, response, authentication);
            return;
        }
        MfaPolicy policy = policyProvider.policyFor(user);
        if (!policy.enabled()) {
            delegate.onAuthenticationSuccess(request, response, authentication);
            return;
        }
        try {
            UserSessionClientInfo clientInfo = clientInfoSource.buildDetails(request);
            Collection<String> methods = Set.of("pwd");
            if (policy.methods().isEmpty()) {
                delegate.onAuthenticationSuccess(request, response, authentication);
                return;
            }
            if (transactionService == null) {
                failureHandler.onAuthenticationFailure(
                        request,
                        response,
                        new AuthenticationServiceException("MFA transaction storage is not configured"));
                return;
            }
            if (policy.methods().contains("email") && emailMfaService == null) {
                throw new AuthenticationServiceException("Email MFA is not configured");
            }
            MfaLoginTransactionService.StartedTransaction transaction =
                    transactionService.begin(user, policy, methods, clientInfo, clock.instant());
            if (policy.methods().contains("email")) {
                emailMfaService.beginLogin(user.getUsername(), transaction.token(), transaction.expiresAt());
            }
            response.setStatus(HttpStatus.ACCEPTED.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding("UTF-8");
            response.setHeader("Cache-Control", "no-store");
            response.setHeader("Pragma", "no-cache");
            jsonMapper.writeValue(
                    response.getOutputStream(),
                    new MfaRequiredResponse(
                            "mfa_required", transaction.token(), transaction.methods(), transaction.expiresAt()));
        } catch (RuntimeException exception) {
            failureHandler.onAuthenticationFailure(
                    request,
                    response,
                    new AuthenticationServiceException("Authentication could not be completed", exception));
        }
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication)
            throws IOException, ServletException {
        onAuthenticationSuccess(request, response, authentication);
    }

    private record MfaRequiredResponse(
            String status, String transaction_token, Set<String> methods, java.time.Instant expires_at) {}

    private static Set<String> union(Set<String> methods, String method) {
        java.util.HashSet<String> result = new java.util.HashSet<>(methods);
        result.add(method);
        return Set.copyOf(result);
    }
}

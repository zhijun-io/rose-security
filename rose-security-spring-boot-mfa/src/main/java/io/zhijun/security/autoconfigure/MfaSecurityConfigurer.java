package io.zhijun.security.autoconfigure;

import io.zhijun.security.core.MfaPolicy;
import io.zhijun.security.core.MfaPolicyProvider;
import java.time.Clock;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;
import tools.jackson.databind.json.JsonMapper;

/** Adds the optional MFA filters to a host-owned SecurityFilterChain. */
public final class MfaSecurityConfigurer extends AbstractHttpConfigurer<MfaSecurityConfigurer, HttpSecurity> {

    private final AuthenticationManager factorAuthenticationManager;
    private final MfaProperties mfaProperties;
    private final JsonMapper jsonMapper;
    private final MfaAwareLoginSuccessHandler loginSuccessHandler;
    private final AuthenticationFailureHandler failureHandler;
    private final MfaLoginTransactionService transactionService;
    private final MfaPolicyProvider policyProvider;
    private final TotpMfaService totpService;
    private final EmailMfaService emailService;
    private final WebAuthnMfaService webAuthnService;
    private final Clock clock;

    MfaSecurityConfigurer(
            AuthenticationManager factorAuthenticationManager,
            MfaProperties mfaProperties,
            JsonMapper jsonMapper,
            MfaAwareLoginSuccessHandler loginSuccessHandler,
            AuthenticationFailureHandler failureHandler,
            MfaLoginTransactionService transactionService,
            MfaPolicyProvider policyProvider,
            TotpMfaService totpService,
            EmailMfaService emailService,
            WebAuthnMfaService webAuthnService,
            Clock clock) {
        this.factorAuthenticationManager = factorAuthenticationManager;
        this.mfaProperties = mfaProperties;
        this.jsonMapper = jsonMapper;
        this.loginSuccessHandler = loginSuccessHandler;
        this.failureHandler = failureHandler;
        this.transactionService = transactionService;
        this.policyProvider = policyProvider;
        this.totpService = totpService;
        this.emailService = emailService;
        this.webAuthnService = webAuthnService;
        this.clock = clock;
    }

    @Override
    public void init(HttpSecurity http) {
        http.setSharedObject(AuthenticationSuccessHandler.class, loginSuccessHandler);
    }

    @Override
    public void configure(HttpSecurity http) {
        MfaProperties.Mfa mfa = mfaProperties.mfa();
        MfaProperties.Endpoints endpoints = mfaProperties.endpoints();
        if (transactionService != null) {
            AuthenticationManager mfaAuthenticationManager = authentication -> {
                if (!(authentication instanceof MfaVerificationAuthenticationToken request)) {
                    throw new BadCredentialsException("Authentication failed");
                }
                try {
                    MfaLoginTransactionService.VerifiedLogin verified = transactionService.verify(
                            request.transactionToken(),
                            request.method(),
                            (String) request.getCredentials(),
                            factorAuthenticationManager,
                            clock.instant(),
                            mfa.maximumAttempts());
                    if (!(verified.authentication().getPrincipal() instanceof UserDetails user)) {
                        throw new BadCredentialsException("Authentication failed");
                    }
                    new AccountStatusUserDetailsChecker().check(user);
                    MfaPolicy currentPolicy = policyProvider.policyFor(user);
                    if (!currentPolicy.enabled() || !currentPolicy.methods().contains(verified.method())) {
                        throw new BadCredentialsException("Authentication failed");
                    }
                    UsernamePasswordAuthenticationToken completed = UsernamePasswordAuthenticationToken.authenticated(
                            user, null, verified.authentication().getAuthorities());
                    completed.setDetails(
                            new MfaLoginCompletion(verified.transaction(), verified.method(), clock.instant()));
                    return completed;
                } finally {
                    request.eraseCredentials();
                }
            };
            AuthenticationFilter filter = new AuthenticationFilter(
                    mfaAuthenticationManager, new JsonMfaVerificationAuthenticationConverter(jsonMapper));
            filter.setRequestMatcher(post(path(endpoints, endpoints.mfaVerify())));
            filter.setSecurityContextRepository(new NullSecurityContextRepository());
            filter.setSuccessHandler(loginSuccessHandler);
            filter.setFailureHandler(failureHandler);
            http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
        }

        TotpMfaService configuredTotpService = mfa.methods().contains("totp") ? totpService : null;
        EmailMfaService configuredEmailService = mfa.methods().contains("email") ? emailService : null;
        WebAuthnMfaService configuredWebAuthnService = mfa.methods().contains("webauthn") ? webAuthnService : null;
        if (configuredTotpService != null || configuredEmailService != null || configuredWebAuthnService != null) {
            MfaManagementFilter filter = new MfaManagementFilter(
                    endpoints.meMfa(),
                    path(endpoints, endpoints.webauthnOptions()),
                    configuredTotpService,
                    configuredEmailService,
                    mfa,
                    mfa.totpIssuer(),
                    jsonMapper,
                    failureHandler,
                    clock,
                    configuredWebAuthnService,
                    transactionService);
            http.addFilterAfter(filter, BearerTokenAuthenticationFilter.class);
        }
    }

    private static RequestMatcher post(String path) {
        return request -> HttpMethod.POST.matches(request.getMethod()) && path.equals(request.getServletPath());
    }

    private static String path(MfaProperties.Endpoints endpoints, String endpoint) {
        return endpoints.basePath().replaceAll("/$", "") + "/" + endpoint.replaceAll("^/", "");
    }
}

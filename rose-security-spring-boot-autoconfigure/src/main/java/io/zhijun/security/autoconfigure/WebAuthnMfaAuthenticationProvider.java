package io.zhijun.security.autoconfigure;

import io.zhijun.security.core.MfaFactorAuthenticationToken;
import java.time.Clock;
import java.util.Objects;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/** Spring Security provider for a WebAuthn assertion in the pending MFA login transaction. */
public class WebAuthnMfaAuthenticationProvider implements AuthenticationProvider {

    private final WebAuthnMfaService service;
    private final UserDetailsService users;
    private final Clock clock;
    private final AccountStatusUserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();

    public WebAuthnMfaAuthenticationProvider(WebAuthnMfaService service, UserDetailsService users, Clock clock) {
        this.service = Objects.requireNonNull(service);
        this.users = Objects.requireNonNull(users);
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        if (!(authentication instanceof MfaFactorAuthenticationToken request) || !"webauthn".equals(request.method())) {
            return null;
        }
        if (!(request.getCredentials() instanceof String proof)
                || request.transactionToken() == null
                || !service.verifyLogin(
                        (String) request.getPrincipal(), request.transactionToken(), proof, clock.instant())) {
            throw new BadCredentialsException("Authentication failed");
        }
        try {
            var user = users.loadUserByUsername((String) request.getPrincipal());
            userDetailsChecker.check(user);
            return UsernamePasswordAuthenticationToken.authenticated(user, null, user.getAuthorities());
        } catch (UsernameNotFoundException exception) {
            throw new BadCredentialsException("Authentication failed");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return MfaFactorAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

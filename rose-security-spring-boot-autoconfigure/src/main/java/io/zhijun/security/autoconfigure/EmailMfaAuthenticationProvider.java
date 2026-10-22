package io.zhijun.security.autoconfigure;

import io.zhijun.security.core.MfaFactorAuthenticationToken;
import java.time.Clock;
import java.util.Objects;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/** Spring Security provider for email MFA login proofs. */
public class EmailMfaAuthenticationProvider implements AuthenticationProvider {

    private final EmailMfaService service;
    private final UserDetailsService userDetailsService;
    private final Clock clock;
    private final AccountStatusUserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();

    public EmailMfaAuthenticationProvider(EmailMfaService service, UserDetailsService userDetailsService, Clock clock) {
        this.service = Objects.requireNonNull(service);
        this.userDetailsService = Objects.requireNonNull(userDetailsService);
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        if (!(authentication instanceof MfaFactorAuthenticationToken request) || !"email".equals(request.method())) {
            return null;
        }
        if (!(request.getCredentials() instanceof String code)
                || !service.verifyLogin(
                        (String) request.getPrincipal(), request.transactionToken(), code, clock.instant())) {
            throw new BadCredentialsException("Authentication failed");
        }
        try {
            UserDetails user = userDetailsService.loadUserByUsername((String) request.getPrincipal());
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

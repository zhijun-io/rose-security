package io.zhijun.security.autoconfigure;

import io.zhijun.security.core.MfaFactorAuthenticationToken;
import java.util.Objects;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/** Spring Security provider for the TOTP MFA method. */
public class TotpAuthenticationProvider implements AuthenticationProvider {

    private final TotpMfaService totpMfaService;
    private final UserDetailsService userDetailsService;
    private final AccountStatusUserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();

    public TotpAuthenticationProvider(TotpMfaService totpMfaService, UserDetailsService userDetailsService) {
        this.totpMfaService = Objects.requireNonNull(totpMfaService);
        this.userDetailsService = Objects.requireNonNull(userDetailsService);
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        if (!(authentication instanceof MfaFactorAuthenticationToken request) || !"totp".equals(request.method())) {
            return null;
        }
        if (!(request.getCredentials() instanceof String code)) {
            throw new BadCredentialsException("Authentication failed");
        }
        if (!totpMfaService.verify((String) request.getPrincipal(), code)) {
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

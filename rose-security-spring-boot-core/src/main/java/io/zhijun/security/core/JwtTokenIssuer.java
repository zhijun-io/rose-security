package io.zhijun.security.core;

import java.time.Instant;
import java.util.Collection;
import org.springframework.security.core.userdetails.UserDetails;

/** Issues this application's short-lived API access tokens after successful authentication. */
public interface JwtTokenIssuer {

    IssuedAccessToken issue(
            UserDetails principal,
            String sessionId,
            Collection<String> authenticationMethods,
            Instant authenticatedAt,
            long securityVersion);
}

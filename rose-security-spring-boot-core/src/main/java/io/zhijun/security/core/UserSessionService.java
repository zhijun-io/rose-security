package io.zhijun.security.core;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import org.springframework.security.core.userdetails.UserDetails;

/** Application service for creating, rotating, querying, and revoking token sessions. */
public interface UserSessionService {

    IssuedSessionTokens create(
            UserDetails principal,
            Collection<String> authenticationMethods,
            Instant authenticatedAt,
            UserSessionClientInfo clientInfo);

    IssuedSessionTokens refresh(String refreshToken);

    boolean revoke(String username, String sessionId);

    int revokeAll(String username);

    List<UserSessionView> findActiveSessions(String username);
}

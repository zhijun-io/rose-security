package io.zhijun.security.autoconfigure;

import io.zhijun.security.core.IssuedAccessToken;
import io.zhijun.security.core.IssuedSessionTokens;
import io.zhijun.security.core.JwtTokenIssuer;
import io.zhijun.security.core.UserSecurityVersionProvider;
import io.zhijun.security.core.UserSessionClientInfo;
import io.zhijun.security.core.UserSessionConcurrencyPolicy;
import io.zhijun.security.core.UserSessionException;
import io.zhijun.security.core.UserSessionService;
import io.zhijun.security.core.UserSessionStore;
import io.zhijun.security.core.UserSessionView;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

final class RefreshUserSessionService implements UserSessionService {

    private static final int TOKEN_BYTES = 32;

    private final JwtTokenIssuer jwtTokenIssuer;
    private final UserSessionStore sessionStore;
    private final UserDetailsService userDetailsService;
    private final UserSecurityVersionProvider securityVersionProvider;
    private final UserSessionConcurrencyPolicy concurrencyPolicy;
    private final AuthSecurityProperties properties;
    private final Clock clock;
    private final SecureRandom secureRandom;

    RefreshUserSessionService(
            JwtTokenIssuer jwtTokenIssuer,
            UserSessionStore sessionStore,
            UserDetailsService userDetailsService,
            UserSecurityVersionProvider securityVersionProvider,
            UserSessionConcurrencyPolicy concurrencyPolicy,
            AuthSecurityProperties properties,
            Clock clock,
            SecureRandom secureRandom) {
        this.jwtTokenIssuer = jwtTokenIssuer;
        this.sessionStore = sessionStore;
        this.userDetailsService = userDetailsService;
        this.securityVersionProvider = securityVersionProvider;
        this.concurrencyPolicy = concurrencyPolicy;
        this.properties = properties;
        this.clock = clock;
        this.secureRandom = secureRandom;
    }

    @Override
    public IssuedSessionTokens create(
            UserDetails principal,
            Collection<String> authenticationMethods,
            Instant authenticatedAt,
            UserSessionClientInfo clientInfo) {
        validatePrincipal(principal);
        if (authenticationMethods == null || authenticationMethods.isEmpty()) {
            throw new IllegalArgumentException("At least one authentication method is required");
        }
        Objects.requireNonNull(authenticatedAt, "authenticatedAt must not be null");

        String username = principal.getUsername();
        List<String> storedAuthenticationMethods = List.copyOf(authenticationMethods);
        long securityVersion = securityVersionProvider.currentVersion(username);
        if (securityVersion < 0) {
            throw new IllegalStateException("UserSecurityVersionProvider returned a negative version");
        }
        Instant now = now();
        String sessionId = newOpaqueToken();
        if (!properties.jwt().refreshEnabled()) {
            IssuedAccessToken accessToken = jwtTokenIssuer.issue(
                    principal, sessionId, storedAuthenticationMethods, authenticatedAt, securityVersion);
            UserSessionStore.UserSession session = new UserSessionStore.UserSession(
                    sessionId,
                    username,
                    securityVersion,
                    authenticatedAt,
                    storedAuthenticationMethods,
                    now,
                    now,
                    accessToken.expiresAt(),
                    accessToken.expiresAt(),
                    null,
                    clientInfo == null ? null : clientInfo.clientIp(),
                    clientInfo == null ? "未知设备" : clientInfo.device());
            createSession(session, null);
            return new IssuedSessionTokens(accessToken.value(), accessToken.expiresAt(), null, null, sessionId);
        }

        Instant absoluteExpiresAt = now.plus(properties.jwt().refreshAbsoluteTtl());
        String refreshToken = newOpaqueToken();
        Instant refreshExpiresAt = min(now.plus(properties.jwt().refreshTtl()), absoluteExpiresAt);
        UserSessionStore.UserSession session = new UserSessionStore.UserSession(
                sessionId,
                username,
                securityVersion,
                authenticatedAt,
                storedAuthenticationMethods,
                now,
                now,
                refreshExpiresAt,
                absoluteExpiresAt,
                null,
                clientInfo == null ? null : clientInfo.clientIp(),
                clientInfo == null ? "未知设备" : clientInfo.device());
        IssuedSessionTokens tokens = issueTokens(
                principal, session, refreshToken, refreshExpiresAt, storedAuthenticationMethods, authenticatedAt);
        createSession(session, hash(refreshToken));
        return tokens;
    }

    @Override
    public IssuedSessionTokens refresh(String refreshToken) {
        if (!properties.jwt().refreshEnabled()) {
            throw invalidRefreshToken();
        }
        if (!validOpaqueToken(refreshToken)) {
            throw invalidRefreshToken();
        }
        Instant now = now();
        String presentedHash = hash(refreshToken);
        String replacementToken = newOpaqueToken();
        UserSessionStore.RotationResult rotation = sessionStore.rotate(
                presentedHash, hash(replacementToken), properties.jwt().refreshTtl(), now);
        if (rotation.status() == UserSessionStore.RotationStatus.REPLAYED) {
            throw new UserSessionException(UserSessionException.Reason.REFRESH_TOKEN_REPLAYED);
        }
        if (rotation.status() != UserSessionStore.RotationStatus.ROTATED || rotation.session() == null) {
            throw invalidRefreshToken();
        }

        UserSessionStore.UserSession rotatedSession = rotation.session();
        try {
            UserDetails principal = validateCurrentUser(rotatedSession);
            return issueTokens(
                    principal,
                    rotatedSession,
                    replacementToken,
                    rotatedSession.expiresAt(),
                    rotatedSession.authenticationMethods(),
                    rotatedSession.authenticatedAt());
        } catch (RuntimeException exception) {
            sessionStore.revoke(rotatedSession.sessionId(), rotatedSession.username(), now());
            throw exception;
        }
    }

    @Override
    public boolean revoke(String username, String sessionId) {
        if (username == null || username.isBlank() || sessionId == null || sessionId.isBlank()) {
            return false;
        }
        return sessionStore.revoke(sessionId, username, now());
    }

    @Override
    public int revokeAll(String username) {
        if (username == null || username.isBlank()) {
            return 0;
        }
        return sessionStore.revokeAll(username, now());
    }

    @Override
    public List<UserSessionView> findActiveSessions(String username) {
        if (username == null || username.isBlank()) {
            return List.of();
        }
        return sessionStore.findActiveSessions(username, now()).stream()
                .map(session -> new UserSessionView(
                        session.sessionId(),
                        session.createdAt(),
                        session.lastUsedAt(),
                        session.expiresAt(),
                        session.absoluteExpiresAt(),
                        session.clientIp(),
                        session.device()))
                .toList();
    }

    private IssuedSessionTokens issueTokens(
            UserDetails principal,
            UserSessionStore.UserSession session,
            String refreshToken,
            Instant refreshExpiresAt,
            Collection<String> authenticationMethods,
            Instant authenticatedAt) {
        IssuedAccessToken accessToken = jwtTokenIssuer.issue(
                principal, session.sessionId(), authenticationMethods, authenticatedAt, session.securityVersion());
        return new IssuedSessionTokens(
                accessToken.value(), accessToken.expiresAt(), refreshToken, refreshExpiresAt, session.sessionId());
    }

    private UserDetails validateCurrentUser(UserSessionStore.UserSession session) {
        UserDetails principal = loadCurrentUser(session);
        long currentVersion = securityVersionProvider.currentVersion(session.username());
        if (!session.username().equals(principal.getUsername())
                || !principal.isEnabled()
                || !principal.isAccountNonLocked()
                || !principal.isAccountNonExpired()
                || !principal.isCredentialsNonExpired()
                || currentVersion != session.securityVersion()) {
            throw new UserSessionException(UserSessionException.Reason.SESSION_INVALIDATED);
        }
        return principal;
    }

    private void createSession(UserSessionStore.UserSession session, String refreshTokenHash) {
        UserSessionConcurrencyPolicy.Policy policy = concurrencyPolicy.forUser(session.username());
        UserSessionStore.SessionCreationResult result = sessionStore.create(session, refreshTokenHash, policy);
        if (result == UserSessionStore.SessionCreationResult.LIMIT_REACHED) {
            throw new UserSessionException(UserSessionException.Reason.SESSION_LIMIT_REACHED);
        }
    }

    private UserDetails loadCurrentUser(UserSessionStore.UserSession session) {
        try {
            return userDetailsService.loadUserByUsername(session.username());
        } catch (UsernameNotFoundException exception) {
            throw new UserSessionException(UserSessionException.Reason.USER_UNAVAILABLE);
        }
    }

    private static void validatePrincipal(UserDetails principal) {
        if (principal == null
                || principal.getUsername() == null
                || principal.getUsername().isBlank()
                || !principal.isEnabled()
                || !principal.isAccountNonLocked()
                || !principal.isAccountNonExpired()
                || !principal.isCredentialsNonExpired()) {
            throw new UserSessionException(UserSessionException.Reason.USER_UNAVAILABLE);
        }
    }

    private Instant now() {
        return clock.instant().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
    }

    private String newOpaqueToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static boolean validOpaqueToken(String value) {
        return value != null
                && value.length() == 43
                && value.chars()
                        .allMatch(character -> (character >= 'A' && character <= 'Z')
                                || (character >= 'a' && character <= 'z')
                                || (character >= '0' && character <= '9')
                                || character == '-'
                                || character == '_');
    }

    private static String hash(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static Instant min(Instant first, Instant second) {
        return first.isBefore(second) ? first : second;
    }

    private static UserSessionException invalidRefreshToken() {
        return new UserSessionException(UserSessionException.Reason.INVALID_REFRESH_TOKEN);
    }
}

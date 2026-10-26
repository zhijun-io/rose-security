package io.zhijun.security.autoconfigure;

import io.zhijun.security.core.UserSessionConcurrencyPolicy;
import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;
import org.springframework.validation.annotation.Validated;

/** Static deployment settings for authentication and token features. */
@Validated
@ConfigurationProperties("auth.security")
public record AuthSecurityProperties(
        Boolean enabled,
        @Valid Jwt jwt,
        @Valid Endpoints endpoints,
        @Valid SessionConcurrency sessionConcurrency,
        @Valid RemoteLogin remoteLogin) {

    @ConstructorBinding
    public AuthSecurityProperties {
        enabled = enabled == null || enabled;
        jwt = jwt == null ? Jwt.defaults() : jwt;
        endpoints = endpoints == null ? Endpoints.defaults() : endpoints;
        sessionConcurrency = sessionConcurrency == null ? SessionConcurrency.defaults() : sessionConcurrency;
        remoteLogin = remoteLogin == null ? RemoteLogin.defaults() : remoteLogin;
    }

    public AuthSecurityProperties(Boolean enabled, Jwt jwt, Endpoints endpoints) {
        this(enabled, jwt, endpoints, null, null);
    }

    public record SessionConcurrency(
            @Min(0) int maximumActiveSessions, UserSessionConcurrencyPolicy.LimitBehavior whenLimitReached) {

        public SessionConcurrency {
            whenLimitReached =
                    whenLimitReached == null ? UserSessionConcurrencyPolicy.LimitBehavior.DENY_NEW : whenLimitReached;
        }

        public static SessionConcurrency defaults() {
            return new SessionConcurrency(0, null);
        }
    }

    public record RemoteLogin(boolean enabled) {

        public static RemoteLogin defaults() {
            return new RemoteLogin(false);
        }
    }

    @AssertTrue(message = "Token lifetimes must be positive and refresh TTL cannot exceed the absolute TTL")
    public boolean isTokenLifetimeConfigurationValid() {
        return positive(jwt.accessTtl())
                && (!jwt.refreshEnabled()
                        || (positive(jwt.refreshTtl())
                                && positive(jwt.refreshAbsoluteTtl())
                                && jwt.refreshTtl().compareTo(jwt.refreshAbsoluteTtl()) <= 0));
    }

    @AssertTrue(message = "Enabled token issuance requires issuer and audience")
    public boolean isTokenSigningConfigurationValid() {
        return !jwt.issuer().isBlank() && !jwt.audience().isBlank();
    }

    private static boolean positive(Duration value) {
        return value != null && !value.isZero() && !value.isNegative();
    }

    public record Jwt(
            Boolean refreshEnabled,
            Duration accessTtl,
            Duration refreshTtl,
            Duration refreshAbsoluteTtl,
            String issuer,
            String audience,
            String privateKeyFile,
            String publicKeyFile,
            String activeKeyId) {

        @ConstructorBinding
        public Jwt {
            refreshEnabled = refreshEnabled == null || refreshEnabled;
            accessTtl = accessTtl == null ? Duration.ofMinutes(10) : accessTtl;
            refreshTtl = refreshTtl == null ? Duration.ofDays(14) : refreshTtl;
            refreshAbsoluteTtl = refreshAbsoluteTtl == null ? Duration.ofDays(30) : refreshAbsoluteTtl;
            issuer = issuer == null ? "" : issuer;
            audience = audience == null ? "" : audience;
            privateKeyFile = blankToNull(privateKeyFile);
            publicKeyFile = blankToNull(publicKeyFile);
            activeKeyId = blankToNull(activeKeyId);
        }

        @AssertTrue(message = "JWT private-key-file and public-key-file must be configured together")
        public boolean isKeyFileConfigurationValid() {
            return (privateKeyFile == null) == (publicKeyFile == null);
        }

        public static Jwt defaults() {
            return new Jwt(true, null, null, null, null, null, null, null, null);
        }

        private static String blankToNull(String value) {
            return value == null || value.isBlank() ? null : value;
        }
    }

    public record Endpoints(
            @NotBlank String basePath,
            @NotBlank String login,
            @NotBlank String refresh,
            @NotBlank String logout,
            @NotBlank String logoutAll) {

        @ConstructorBinding
        public Endpoints {
            basePath = basePath == null ? "/api/auth" : basePath;
            login = login == null ? "/login" : login;
            refresh = refresh == null ? "/refresh" : refresh;
            logout = logout == null ? "/logout" : logout;
            logoutAll = logoutAll == null ? "/logout-all" : logoutAll;
        }

        @AssertTrue(message = "Authentication endpoint paths must be absolute paths and must not collide")
        public boolean isPathConfigurationValid() {
            return absolute(basePath)
                    && absolute(login)
                    && absolute(refresh)
                    && absolute(logout)
                    && absolute(logoutAll)
                    && !login.equals(refresh)
                    && !login.equals(logout)
                    && !login.equals(logoutAll)
                    && !refresh.equals(logout)
                    && !refresh.equals(logoutAll)
                    && !logout.equals(logoutAll);
        }

        private static boolean absolute(String path) {
            return path != null && path.startsWith("/") && !path.contains("//");
        }

        public static Endpoints defaults() {
            return new Endpoints("/api/auth", "/login", "/refresh", "/logout", "/logout-all");
        }
    }
}

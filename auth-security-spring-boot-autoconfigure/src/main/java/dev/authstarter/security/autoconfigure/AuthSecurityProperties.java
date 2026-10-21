package dev.authstarter.security.autoconfigure;

import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/** Static deployment settings. Runtime MFA and OAuth provider policies are managed by their repositories. */
@Validated
@ConfigurationProperties("auth.security")
public record AuthSecurityProperties(
        Boolean enabled, @Valid Token token, @Valid Endpoints endpoints) {

    public AuthSecurityProperties {
        enabled = enabled == null || enabled;
        token = token == null ? Token.defaults() : token;
        endpoints = endpoints == null ? Endpoints.defaults() : endpoints;
    }

    public record Token(
            boolean enabled,
            Duration accessTtl,
            Duration refreshTtl,
            Duration refreshAbsoluteTtl,
            String issuer,
            String audience,
            String signingAlgorithm,
            String keyProvider) {

        public Token {
            accessTtl = accessTtl == null ? Duration.ofMinutes(10) : accessTtl;
            refreshTtl = refreshTtl == null ? Duration.ofDays(14) : refreshTtl;
            refreshAbsoluteTtl = refreshAbsoluteTtl == null ? Duration.ofDays(30) : refreshAbsoluteTtl;
            issuer = issuer == null ? "" : issuer;
            audience = audience == null ? "" : audience;
            signingAlgorithm = signingAlgorithm == null ? "RS256" : signingAlgorithm;
            keyProvider = keyProvider == null ? "" : keyProvider;
        }

        @AssertTrue(message = "Token lifetimes must be positive and refresh TTL cannot exceed the absolute TTL")
        public boolean isLifetimeConfigurationValid() {
            return positive(accessTtl)
                    && positive(refreshTtl)
                    && positive(refreshAbsoluteTtl)
                    && refreshTtl.compareTo(refreshAbsoluteTtl) <= 0;
        }

        @AssertTrue(message = "Enabled token issuance requires issuer, audience, RS256 and a key provider")
        public boolean isSigningConfigurationValid() {
            return !enabled
                    || (!issuer.isBlank()
                            && !audience.isBlank()
                            && "RS256".equals(signingAlgorithm)
                            && !keyProvider.isBlank());
        }

        private static boolean positive(Duration value) {
            return value != null && !value.isZero() && !value.isNegative();
        }

        public static Token defaults() {
            return new Token(false, null, null, null, null, null, null, null);
        }
    }

    public record Endpoints(
            @NotBlank String basePath,
            @NotBlank String login,
            @NotBlank String refresh,
            @NotBlank String logout,
            @NotBlank String logoutAll) {

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

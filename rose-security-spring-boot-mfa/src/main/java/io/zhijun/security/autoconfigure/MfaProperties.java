package io.zhijun.security.autoconfigure;

import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Min;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;
import org.springframework.validation.annotation.Validated;

/** MFA settings. The existing auth.security.mfa and auth.security.endpoints keys are retained. */
@Validated
@ConfigurationProperties("auth.security")
public record MfaProperties(@Valid Mfa mfa, @Valid Endpoints endpoints) {

    @ConstructorBinding
    public MfaProperties {
        mfa = mfa == null ? Mfa.defaults() : mfa;
        endpoints = endpoints == null ? Endpoints.defaults() : endpoints;
    }

    public record Mfa(
            boolean enabled,
            Set<@jakarta.validation.constraints.Pattern(regexp = "[a-z][a-z0-9-]{0,31}") String> methods,
            Duration transactionTtl,
            @Min(1) Integer maximumAttempts,
            String totpIssuer,
            String webauthnRpId,
            Set<String> webauthnAllowedOrigins) {

        @ConstructorBinding
        public Mfa {
            methods = methods == null ? Set.of() : Set.copyOf(methods);
            transactionTtl = transactionTtl == null ? Duration.ofMinutes(5) : transactionTtl;
            maximumAttempts = maximumAttempts == null ? 5 : maximumAttempts;
            totpIssuer = totpIssuer == null || totpIssuer.isBlank() ? "Rose Security" : totpIssuer;
            webauthnRpId = webauthnRpId == null || webauthnRpId.isBlank() ? null : webauthnRpId;
            webauthnAllowedOrigins = webauthnAllowedOrigins == null ? Set.of() : Set.copyOf(webauthnAllowedOrigins);
        }

        @AssertTrue(message = "Enabled MFA requires at least one method")
        public boolean isPolicyConfigurationValid() {
            return !enabled || !methods.isEmpty();
        }

        @AssertTrue(message = "WebAuthn MFA requires an RP ID and at least one allowed origin")
        public boolean isWebauthnConfigurationValid() {
            return !methods.contains("webauthn")
                    || (webauthnRpId != null
                            && !webauthnAllowedOrigins.isEmpty()
                            && webauthnAllowedOrigins.stream().noneMatch(String::isBlank));
        }

        @AssertTrue(message = "MFA transaction TTL must be positive")
        public boolean isTransactionTtlPositive() {
            return transactionTtl != null && !transactionTtl.isZero() && !transactionTtl.isNegative();
        }

        public static Mfa defaults() {
            return new Mfa(false, Set.of(), null, 5, null, null, Set.of());
        }
    }

    public record Endpoints(
            String basePath,
            String login,
            String refresh,
            String logout,
            String logoutAll,
            String mfaVerify,
            String meMfa,
            String webauthnOptions) {

        @ConstructorBinding
        public Endpoints {
            basePath = basePath == null ? "/api/auth" : basePath;
            login = login == null ? "/login" : login;
            refresh = refresh == null ? "/refresh" : refresh;
            logout = logout == null ? "/logout" : logout;
            logoutAll = logoutAll == null ? "/logout-all" : logoutAll;
            mfaVerify = mfaVerify == null ? "/mfa/verify" : mfaVerify;
            meMfa = meMfa == null ? "/api/me/mfa" : meMfa;
            webauthnOptions = webauthnOptions == null ? "/mfa/webauthn/options" : webauthnOptions;
        }

        public static Endpoints defaults() {
            return new Endpoints(null, null, null, null, null, null, null, null);
        }

        @AssertTrue(message = "MFA endpoint paths must be absolute paths and must not collide")
        public boolean isPathConfigurationValid() {
            List<String> paths = List.of(
                    join(basePath, login),
                    join(basePath, refresh),
                    join(basePath, logout),
                    join(basePath, logoutAll),
                    join(basePath, mfaVerify),
                    join(basePath, webauthnOptions),
                    meMfa);
            return absolute(basePath)
                    && absolute(meMfa)
                    && paths.stream().allMatch(Endpoints::absolute)
                    && paths.stream().distinct().count() == paths.size();
        }

        private static String join(String basePath, String path) {
            return basePath.replaceAll("/$", "") + "/" + path.replaceAll("^/", "");
        }

        private static boolean absolute(String path) {
            return path != null && path.startsWith("/") && !path.contains("//");
        }
    }
}

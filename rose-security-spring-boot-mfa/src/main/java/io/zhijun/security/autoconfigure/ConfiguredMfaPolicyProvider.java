package io.zhijun.security.autoconfigure;

import io.zhijun.security.core.MfaPolicy;
import io.zhijun.security.core.MfaPolicyProvider;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import org.springframework.security.core.userdetails.UserDetails;

/** Resolves globally allowed, user-enrolled methods from {@code auth.security.mfa}. */
public class ConfiguredMfaPolicyProvider implements MfaPolicyProvider {

    private static final Set<String> SUPPORTED_METHODS = Set.of("totp", "email", "webauthn");

    private final MfaProperties.Mfa properties;
    private final TotpMfaService totpMfaService;
    private final EmailMfaService emailMfaService;
    private final WebAuthnMfaService webAuthnMfaService;

    public ConfiguredMfaPolicyProvider(
            MfaProperties.Mfa properties,
            TotpMfaService totpMfaService,
            EmailMfaService emailMfaService,
            WebAuthnMfaService webAuthnMfaService) {
        this.properties = Objects.requireNonNull(properties);
        this.totpMfaService = totpMfaService;
        this.emailMfaService = emailMfaService;
        this.webAuthnMfaService = webAuthnMfaService;
        if (properties.enabled()) {
            if (!SUPPORTED_METHODS.containsAll(properties.methods())) {
                throw new IllegalStateException(
                        "Configured MFA methods are not supported by the default policy provider");
            }
            requireService("totp", properties.methods(), totpMfaService);
            requireService("email", properties.methods(), emailMfaService);
            requireService("webauthn", properties.methods(), webAuthnMfaService);
        }
    }

    private static void requireService(String method, Set<String> configuredMethods, Object service) {
        if (configuredMethods.contains(method) && service == null) {
            throw new IllegalStateException("MFA method '" + method
                    + "' is enabled but its service and required host implementations are missing");
        }
    }

    @Override
    public MfaPolicy policyFor(UserDetails user) {
        Objects.requireNonNull(user);
        if (!properties.enabled()) {
            return new MfaPolicy(false, Set.of(), properties.transactionTtl());
        }
        Set<String> enrolledMethods = new LinkedHashSet<>();
        if (properties.methods().contains("totp")
                && totpMfaService != null
                && totpMfaService.isEnrolled(user.getUsername())) {
            enrolledMethods.add("totp");
        }
        if (properties.methods().contains("email")
                && emailMfaService != null
                && emailMfaService.isEnabled(user.getUsername())) {
            enrolledMethods.add("email");
        }
        if (properties.methods().contains("webauthn")
                && webAuthnMfaService != null
                && webAuthnMfaService.isEnrolled(user.getUsername())) {
            enrolledMethods.add("webauthn");
        }
        return new MfaPolicy(true, enrolledMethods, properties.transactionTtl());
    }
}

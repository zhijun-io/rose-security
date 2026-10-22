package io.zhijun.security.autoconfigure;

import io.zhijun.security.core.MfaPolicy;
import io.zhijun.security.core.MfaPolicyProvider;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import org.springframework.security.core.userdetails.UserDetails;

/** Resolves globally allowed, user-enrolled methods from {@code auth.security.mfa}. */
public class ConfiguredMfaPolicyProvider implements MfaPolicyProvider {

    private final AuthSecurityProperties.Mfa properties;
    private final TotpMfaService totpMfaService;
    private final EmailMfaService emailMfaService;
    private final WebAuthnMfaService webAuthnMfaService;

    public ConfiguredMfaPolicyProvider(
            AuthSecurityProperties.Mfa properties, TotpMfaService totpMfaService, EmailMfaService emailMfaService) {
        this(properties, totpMfaService, emailMfaService, null);
    }

    public ConfiguredMfaPolicyProvider(
            AuthSecurityProperties.Mfa properties,
            TotpMfaService totpMfaService,
            EmailMfaService emailMfaService,
            WebAuthnMfaService webAuthnMfaService) {
        this.properties = Objects.requireNonNull(properties);
        this.totpMfaService = totpMfaService;
        this.emailMfaService = emailMfaService;
        this.webAuthnMfaService = webAuthnMfaService;
    }

    @Override
    public MfaPolicy policyFor(UserDetails user) {
        Objects.requireNonNull(user);
        Set<String> enrolledMethods = new LinkedHashSet<>();
        if (properties.enabled()
                && properties.methods().contains("totp")
                && totpMfaService != null
                && totpMfaService.isEnrolled(user.getUsername())) {
            enrolledMethods.add("totp");
        }
        if (properties.enabled()
                && properties.methods().contains("email")
                && emailMfaService != null
                && emailMfaService.isEnabled(user.getUsername())) {
            enrolledMethods.add("email");
        }
        if (properties.enabled()
                && properties.methods().contains("webauthn")
                && webAuthnMfaService != null
                && webAuthnMfaService.isEnrolled(user.getUsername())) {
            enrolledMethods.add("webauthn");
        }
        return new MfaPolicy(properties.enabled(), enrolledMethods, properties.transactionTtl());
    }
}

package io.zhijun.security.autoconfigure;

import io.zhijun.security.core.UserSessionConcurrencyPolicy;

/** Default global session limit; applications can replace this bean for user-specific limits. */
public class ConfiguredUserSessionConcurrencyPolicy implements UserSessionConcurrencyPolicy {

    private final AuthSecurityProperties.SessionConcurrency properties;

    public ConfiguredUserSessionConcurrencyPolicy(AuthSecurityProperties.SessionConcurrency properties) {
        this.properties = properties;
    }

    @Override
    public Policy forUser(String username) {
        return new Policy(properties.maximumActiveSessions(), properties.whenLimitReached());
    }
}

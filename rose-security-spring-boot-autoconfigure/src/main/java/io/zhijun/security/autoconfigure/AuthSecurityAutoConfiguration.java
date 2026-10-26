package io.zhijun.security.autoconfigure;

import io.zhijun.security.core.UserSessionConcurrencyPolicy;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/** Registers validated settings and defaults; it deliberately does not create or replace a SecurityFilterChain. */
@AutoConfiguration
@ConditionalOnProperty(prefix = "auth.security", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(AuthSecurityProperties.class)
public class AuthSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(UserSessionConcurrencyPolicy.class)
    UserSessionConcurrencyPolicy authSecurityUserSessionConcurrencyPolicy(AuthSecurityProperties properties) {
        return new ConfiguredUserSessionConcurrencyPolicy(properties.sessionConcurrency());
    }
}

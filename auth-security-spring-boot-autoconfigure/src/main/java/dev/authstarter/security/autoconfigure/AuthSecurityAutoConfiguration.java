package dev.authstarter.security.autoconfigure;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/** Registers validated settings only; it deliberately does not create or replace a SecurityFilterChain. */
@AutoConfiguration
@ConditionalOnProperty(prefix = "auth.security", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(AuthSecurityProperties.class)
public class AuthSecurityAutoConfiguration {}

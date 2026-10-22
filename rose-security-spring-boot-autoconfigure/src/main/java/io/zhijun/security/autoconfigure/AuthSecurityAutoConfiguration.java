package io.zhijun.security.autoconfigure;

import io.zhijun.security.core.EmailMfaStore;
import io.zhijun.security.core.MfaEmailSender;
import io.zhijun.security.core.MfaLoginTransactionStore;
import io.zhijun.security.core.MfaPolicyProvider;
import io.zhijun.security.core.TotpCredentialStore;
import io.zhijun.security.core.UserSessionConcurrencyPolicy;
import java.security.SecureRandom;
import java.time.Clock;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
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

    @Bean
    @ConditionalOnMissingBean(MfaPolicyProvider.class)
    MfaPolicyProvider authSecurityMfaPolicyProvider(
            AuthSecurityProperties properties,
            ObjectProvider<TotpMfaService> totpMfaServices,
            ObjectProvider<EmailMfaService> emailMfaServices,
            ObjectProvider<WebAuthnMfaService> webAuthnMfaServices) {
        return new ConfiguredMfaPolicyProvider(
                properties.mfa(),
                totpMfaServices.getIfAvailable(),
                emailMfaServices.getIfAvailable(),
                webAuthnMfaServices.getIfAvailable());
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(MfaLoginTransactionStore.class)
    MfaLoginTransactionService authSecurityMfaLoginTransactionService(MfaLoginTransactionStore store) {
        return new MfaLoginTransactionService(store, new SecureRandom());
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({EmailMfaStore.class, MfaEmailSender.class})
    EmailMfaService authSecurityEmailMfaService(EmailMfaStore store, MfaEmailSender sender) {
        return new EmailMfaService(store, sender, new SecureRandom());
    }

    @Bean
    @ConditionalOnMissingBean(TotpMfaService.class)
    @ConditionalOnBean(TotpCredentialStore.class)
    TotpMfaService authSecurityTotpMfaService(
            TotpCredentialStore store, AuthSecurityProperties properties, Clock clock) {
        return new TotpMfaService(
                store,
                new SecureRandom(),
                clock,
                properties.mfa().transactionTtl(),
                properties.mfa().maximumAttempts());
    }
}

package io.zhijun.security.autoconfigure;

import io.zhijun.security.core.EmailMfaStore;
import io.zhijun.security.core.MfaEmailSender;
import io.zhijun.security.core.MfaLoginTransactionStore;
import io.zhijun.security.core.MfaPolicyProvider;
import io.zhijun.security.core.TotpCredentialStore;
import io.zhijun.security.core.UserSessionClientInfo;
import jakarta.servlet.http.HttpServletRequest;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import tools.jackson.databind.json.JsonMapper;

@AutoConfiguration(afterName = "io.zhijun.security.autoconfigure.AuthSecurityFilterAutoConfiguration")
@ConditionalOnProperty(prefix = "auth.security", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(MfaProperties.class)
public class MfaAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(MfaPolicyProvider.class)
    MfaPolicyProvider authSecurityMfaPolicyProvider(
            MfaProperties properties,
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
    TotpMfaService authSecurityTotpMfaService(TotpCredentialStore store, MfaProperties properties, Clock clock) {
        return new TotpMfaService(
                store,
                new SecureRandom(),
                clock,
                properties.mfa().transactionTtl(),
                properties.mfa().maximumAttempts());
    }

    @Bean
    @ConditionalOnMissingBean(MfaAwareLoginSuccessHandler.class)
    @ConditionalOnBean(name = "authSecurityLoginSuccessHandler")
    MfaAwareLoginSuccessHandler authSecurityMfaAwareLoginSuccessHandler(
            @Qualifier("authSecurityLoginSuccessHandler") AuthenticationSuccessHandler loginSuccessHandler,
            MfaPolicyProvider mfaPolicyProvider,
            ObjectProvider<MfaLoginTransactionService> transactionServices,
            ObjectProvider<EmailMfaService> emailMfaServices,
            AuthenticationFailureHandler authenticationFailureHandler,
            AuthenticationDetailsSource<HttpServletRequest, UserSessionClientInfo> clientInfoSource,
            JsonMapper jsonMapper,
            Clock clock) {
        return new MfaAwareLoginSuccessHandler(
                loginSuccessHandler,
                mfaPolicyProvider,
                transactionServices.getIfAvailable(),
                emailMfaServices.getIfAvailable(),
                authenticationFailureHandler,
                clientInfoSource,
                jsonMapper,
                clock);
    }

    @Bean
    @ConditionalOnBean(AuthSecurityConfigurer.class)
    @ConditionalOnMissingBean(MfaSecurityConfigurer.class)
    MfaSecurityConfigurer mfaSecurityConfigurer(
            AuthenticationConfiguration authenticationConfiguration,
            ObjectProvider<AuthenticationManager> authenticationManagers,
            MfaProperties mfaProperties,
            JsonMapper jsonMapper,
            MfaAwareLoginSuccessHandler loginSuccessHandler,
            AuthenticationFailureHandler failureHandler,
            ObjectProvider<MfaLoginTransactionService> transactionServices,
            MfaPolicyProvider policyProvider,
            ObjectProvider<AuthenticationProvider> authenticationProviders,
            ObjectProvider<TotpMfaService> totpServices,
            ObjectProvider<EmailMfaService> emailServices,
            ObjectProvider<WebAuthnMfaService> webAuthnServices,
            ObjectProvider<UserDetailsService> users,
            Clock clock)
            throws Exception {
        AuthenticationManager primary = authenticationManagers.getIfAvailable();
        if (primary == null) {
            primary = authenticationConfiguration.getAuthenticationManager();
        }
        List<AuthenticationProvider> factors =
                new ArrayList<>(authenticationProviders.orderedStream().toList());
        UserDetailsService userDetails = users.getIfAvailable();
        TotpMfaService totp = totpServices.getIfAvailable();
        EmailMfaService email = emailServices.getIfAvailable();
        WebAuthnMfaService webAuthn = webAuthnServices.getIfAvailable();
        if (userDetails != null
                && totp != null
                && factors.stream().noneMatch(TotpAuthenticationProvider.class::isInstance)) {
            factors.add(new TotpAuthenticationProvider(totp, userDetails));
        }
        if (userDetails != null
                && email != null
                && factors.stream().noneMatch(EmailMfaAuthenticationProvider.class::isInstance)) {
            factors.add(new EmailMfaAuthenticationProvider(email, userDetails, clock));
        }
        if (userDetails != null
                && webAuthn != null
                && factors.stream().noneMatch(WebAuthnMfaAuthenticationProvider.class::isInstance)) {
            factors.add(new WebAuthnMfaAuthenticationProvider(webAuthn, userDetails, clock));
        }
        return new MfaSecurityConfigurer(
                new ProviderManager(factors, primary),
                mfaProperties,
                jsonMapper,
                loginSuccessHandler,
                failureHandler,
                transactionServices.getIfAvailable(),
                policyProvider,
                totp,
                email,
                webAuthn,
                clock);
    }
}

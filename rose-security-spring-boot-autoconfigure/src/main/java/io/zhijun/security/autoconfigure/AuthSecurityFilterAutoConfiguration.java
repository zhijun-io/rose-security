package io.zhijun.security.autoconfigure;

import io.zhijun.security.core.MfaPolicyProvider;
import io.zhijun.security.core.UserSessionClientInfo;
import io.zhijun.security.core.UserSessionService;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import tools.jackson.databind.json.JsonMapper;

/** Exposes filters as an opt-in configurer; applications retain ownership of their SecurityFilterChain. */
@AutoConfiguration(after = JwtTokenAutoConfiguration.class)
@ConditionalOnProperty(prefix = "auth.security", name = "enabled", havingValue = "true", matchIfMissing = true)
@ConditionalOnBean({UserSessionService.class, JwtDecoder.class})
@ConditionalOnClass(JsonMapper.class)
public class AuthSecurityFilterAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(AuthenticationFailureHandler.class)
    AuthenticationFailureHandler authSecurityAuthenticationFailureHandler() {
        return new AuthenticationEntryPointFailureHandler(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));
    }

    @Bean
    @ConditionalOnMissingBean
    AuthenticationDetailsSource<HttpServletRequest, UserSessionClientInfo>
            authSecurityUserSessionClientInfoDetailsSource() {
        return new DefaultUserSessionClientInfoDetailsSource();
    }

    @Bean("authSecurityLoginSuccessHandler")
    @ConditionalOnMissingBean(name = "authSecurityLoginSuccessHandler")
    AuthenticationSuccessHandler authSecurityLoginSuccessHandler(
            UserSessionService userSessionService,
            AuthenticationDetailsSource<HttpServletRequest, UserSessionClientInfo> authenticationDetailsSource,
            AuthenticationFailureHandler authenticationFailureHandler,
            JsonMapper jsonMapper,
            Clock clock,
            ObjectProvider<RemoteLoginHandler> remoteLoginHandlers,
            AuthSecurityProperties properties) {
        RemoteLoginHandler remoteLoginHandler = remoteLoginHandlers.getIfAvailable();
        if (properties.remoteLogin().enabled() && remoteLoginHandler == null) {
            throw new IllegalStateException(
                    "auth.security.remote-login.enabled=true requires a RemoteLoginHandler bean");
        }
        return new TokenAuthenticationSuccessHandler(
                userSessionService,
                authenticationDetailsSource,
                authenticationFailureHandler,
                jsonMapper,
                clock,
                remoteLoginHandler,
                properties.remoteLogin().enabled());
    }

    @Bean("authSecurityMfaAwareLoginSuccessHandler")
    @ConditionalOnMissingBean(name = "authSecurityMfaAwareLoginSuccessHandler")
    AuthenticationSuccessHandler authSecurityMfaAwareLoginSuccessHandler(
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

    @Bean("authSecurityRefreshSuccessHandler")
    @ConditionalOnMissingBean(name = "authSecurityRefreshSuccessHandler")
    AuthenticationSuccessHandler authSecurityRefreshSuccessHandler(
            AuthenticationFailureHandler authenticationFailureHandler, JsonMapper jsonMapper, Clock clock) {
        return new RefreshTokenAuthenticationSuccessHandler(authenticationFailureHandler, jsonMapper, clock);
    }

    @Bean("authSecurityLogoutHandler")
    @ConditionalOnMissingBean(name = "authSecurityLogoutHandler")
    LogoutHandler authSecurityLogoutHandler(
            UserSessionService userSessionService, JwtDecoder jwtDecoder, AuthSecurityProperties properties) {
        String logoutAllPath = AuthSecurityConfigurer.path(
                properties.endpoints(), properties.endpoints().logoutAll());
        return new UserSessionLogoutHandler(userSessionService, jwtDecoder, logoutAllPath);
    }

    @Bean("authSecurityLogoutSuccessHandler")
    @ConditionalOnMissingBean(name = "authSecurityLogoutSuccessHandler")
    LogoutSuccessHandler authSecurityLogoutSuccessHandler() {
        return new UserSessionLogoutSuccessHandler();
    }

    @Bean
    @ConditionalOnMissingBean(AuthSecurityConfigurer.class)
    AuthSecurityConfigurer authSecurityConfigurer(
            AuthenticationConfiguration authenticationConfiguration,
            ObjectProvider<AuthenticationManager> authenticationManagers,
            UserSessionService userSessionService,
            AuthSecurityProperties properties,
            JsonMapper jsonMapper,
            @Qualifier("authSecurityMfaAwareLoginSuccessHandler") AuthenticationSuccessHandler loginSuccessHandler,
            @Qualifier("authSecurityRefreshSuccessHandler") AuthenticationSuccessHandler refreshSuccessHandler,
            @Qualifier("authSecurityLogoutHandler") LogoutHandler logoutHandler,
            @Qualifier("authSecurityLogoutSuccessHandler") LogoutSuccessHandler logoutSuccessHandler,
            AuthenticationFailureHandler authenticationFailureHandler,
            ObjectProvider<MfaLoginTransactionService> mfaTransactionServices,
            MfaPolicyProvider mfaPolicyProvider,
            ObjectProvider<AuthenticationProvider> authenticationProviders,
            ObjectProvider<TotpMfaService> totpMfaServices,
            ObjectProvider<EmailMfaService> emailMfaServices,
            ObjectProvider<WebAuthnMfaService> webAuthnMfaServices,
            ObjectProvider<UserDetailsService> userDetailsServices,
            Clock clock)
            throws Exception {
        AuthenticationManager authenticationManager = authenticationManagers.getIfAvailable();
        if (authenticationManager == null) {
            authenticationManager = authenticationConfiguration.getAuthenticationManager();
        }
        List<AuthenticationProvider> factorProviders =
                new ArrayList<>(authenticationProviders.orderedStream().toList());
        TotpMfaService totpMfaService = totpMfaServices.getIfAvailable();
        EmailMfaService emailMfaService = emailMfaServices.getIfAvailable();
        WebAuthnMfaService webAuthnMfaService = webAuthnMfaServices.getIfAvailable();
        UserDetailsService userDetailsService = userDetailsServices.getIfAvailable();
        if (totpMfaService != null
                && userDetailsService != null
                && factorProviders.stream().noneMatch(TotpAuthenticationProvider.class::isInstance)) {
            factorProviders.add(new TotpAuthenticationProvider(totpMfaService, userDetailsService));
        }
        if (emailMfaService != null
                && userDetailsService != null
                && factorProviders.stream().noneMatch(EmailMfaAuthenticationProvider.class::isInstance)) {
            factorProviders.add(new EmailMfaAuthenticationProvider(emailMfaService, userDetailsService, clock));
        }
        if (webAuthnMfaService != null
                && userDetailsService != null
                && factorProviders.stream().noneMatch(WebAuthnMfaAuthenticationProvider.class::isInstance)) {
            factorProviders.add(new WebAuthnMfaAuthenticationProvider(webAuthnMfaService, userDetailsService, clock));
        }
        AuthenticationManager factorAuthenticationManager = new ProviderManager(factorProviders, authenticationManager);
        return new AuthSecurityConfigurer(
                authenticationManager,
                userSessionService,
                properties,
                jsonMapper,
                loginSuccessHandler,
                refreshSuccessHandler,
                logoutHandler,
                logoutSuccessHandler,
                authenticationFailureHandler,
                mfaTransactionServices.getIfAvailable(),
                clock,
                mfaPolicyProvider,
                factorAuthenticationManager,
                totpMfaService,
                emailMfaService,
                webAuthnMfaService);
    }
}

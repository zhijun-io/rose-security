package io.zhijun.security.autoconfigure;

import io.zhijun.security.core.UserSessionClientInfo;
import io.zhijun.security.core.UserSessionService;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Clock;
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
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
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
            @Qualifier("authSecurityLoginSuccessHandler") AuthenticationSuccessHandler loginSuccessHandler,
            @Qualifier("authSecurityRefreshSuccessHandler") AuthenticationSuccessHandler refreshSuccessHandler,
            @Qualifier("authSecurityLogoutHandler") LogoutHandler logoutHandler,
            @Qualifier("authSecurityLogoutSuccessHandler") LogoutSuccessHandler logoutSuccessHandler,
            AuthenticationFailureHandler authenticationFailureHandler)
            throws Exception {
        AuthenticationManager authenticationManager = authenticationManagers.getIfAvailable();
        if (authenticationManager == null) {
            authenticationManager = authenticationConfiguration.getAuthenticationManager();
        }
        return new AuthSecurityConfigurer(
                authenticationManager,
                userSessionService,
                properties,
                jsonMapper,
                loginSuccessHandler,
                refreshSuccessHandler,
                logoutHandler,
                logoutSuccessHandler,
                authenticationFailureHandler);
    }
}

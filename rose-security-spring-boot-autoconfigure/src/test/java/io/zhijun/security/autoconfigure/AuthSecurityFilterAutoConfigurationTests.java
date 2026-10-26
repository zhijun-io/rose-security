package io.zhijun.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.zhijun.security.core.UserSessionService;
import java.time.Clock;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import tools.jackson.databind.json.JsonMapper;

class AuthSecurityFilterAutoConfigurationTests {

    @Test
    void createsDefaultHandlersAndUsesAvailableAuthenticationManager() throws Exception {
        var config = new AuthSecurityFilterAutoConfiguration();
        var failure = config.authSecurityAuthenticationFailureHandler();
        var details = config.authSecurityUserSessionClientInfoDetailsSource();
        assertThat(details).isInstanceOf(DefaultUserSessionClientInfoDetailsSource.class);
        AuthenticationSuccessHandler refresh = config.authSecurityRefreshSuccessHandler(
                failure, JsonMapper.builder().build(), Clock.systemUTC());
        LogoutSuccessHandler logoutSuccess = config.authSecurityLogoutSuccessHandler();
        assertThat(refresh).isInstanceOf(RefreshTokenAuthenticationSuccessHandler.class);
        assertThat(logoutSuccess).isInstanceOf(UserSessionLogoutSuccessHandler.class);

        var sessions = mock(UserSessionService.class);
        JwtDecoder decoder = mock(JwtDecoder.class);
        LogoutHandler logout =
                config.authSecurityLogoutHandler(sessions, decoder, new AuthSecurityProperties(null, null, null));
        assertThat(logout).isInstanceOf(UserSessionLogoutHandler.class);
        AuthenticationManager manager = mock(AuthenticationManager.class);
        ObjectProvider<AuthenticationManager> managers = mock(ObjectProvider.class);
        when(managers.getIfAvailable()).thenReturn(manager);
        AuthSecurityConfigurer configurer = config.authSecurityConfigurer(
                mock(AuthenticationConfiguration.class),
                managers,
                sessions,
                new AuthSecurityProperties(null, null, null),
                JsonMapper.builder().build(),
                mock(AuthenticationSuccessHandler.class),
                refresh,
                logout,
                logoutSuccess,
                failure);
        assertThat(configurer).isNotNull();
    }

    @Test
    void requiresHandlerWhenRemoteLoginIsEnabled() {
        var config = new AuthSecurityFilterAutoConfiguration();
        var providers = mock(ObjectProvider.class);
        when(providers.getIfAvailable()).thenReturn(null);
        var properties =
                new AuthSecurityProperties(null, null, null, null, new AuthSecurityProperties.RemoteLogin(true));

        assertThatThrownBy(() -> config.authSecurityLoginSuccessHandler(
                        mock(UserSessionService.class),
                        config.authSecurityUserSessionClientInfoDetailsSource(),
                        config.authSecurityAuthenticationFailureHandler(),
                        JsonMapper.builder().build(),
                        Clock.systemUTC(),
                        providers,
                        properties))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("RemoteLoginHandler");
    }
}

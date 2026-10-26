package io.zhijun.security.autoconfigure;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import io.zhijun.security.core.UserSessionService;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import tools.jackson.databind.json.JsonMapper;

class AuthSecurityConfigurerWiringTests {

    @Test
    void installsLoginAndRefreshAuthenticationFilters() {
        HttpSecurity http = mock(HttpSecurity.class);
        AuthenticationSuccessHandler success = mock(AuthenticationSuccessHandler.class);
        AuthSecurityConfigurer configurer = new AuthSecurityConfigurer(
                mock(AuthenticationManager.class),
                mock(UserSessionService.class),
                new AuthSecurityProperties(null, null, null),
                JsonMapper.builder().build(),
                success,
                mock(AuthenticationSuccessHandler.class),
                mock(LogoutHandler.class),
                mock(LogoutSuccessHandler.class),
                mock(AuthenticationFailureHandler.class));

        configurer.configure(http);

        verify(http, times(2))
                .addFilterBefore(
                        any(AuthenticationFilter.class),
                        eq(org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class));
    }
}

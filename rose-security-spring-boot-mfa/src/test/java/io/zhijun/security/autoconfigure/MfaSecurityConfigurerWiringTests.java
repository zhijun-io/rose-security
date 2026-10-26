package io.zhijun.security.autoconfigure;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import io.zhijun.security.core.MfaPolicyProvider;
import java.time.Clock;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import tools.jackson.databind.json.JsonMapper;

class MfaSecurityConfigurerWiringTests {

    @Test
    void installsVerificationAndConfiguredManagementFilters() {
        HttpSecurity http = mock(HttpSecurity.class);
        var mfa = new MfaProperties.Mfa(true, Set.of("totp"), null, 5, null, null, Set.of());
        var configurer = new MfaSecurityConfigurer(
                mock(AuthenticationManager.class),
                new MfaProperties(mfa, null),
                JsonMapper.builder().build(),
                mock(MfaAwareLoginSuccessHandler.class),
                mock(AuthenticationFailureHandler.class),
                mock(MfaLoginTransactionService.class),
                mock(MfaPolicyProvider.class),
                mock(TotpMfaService.class),
                null,
                null,
                Clock.systemUTC());

        configurer.configure(http);

        verify(http).addFilterBefore(any(AuthenticationFilter.class), eq(UsernamePasswordAuthenticationFilter.class));
        verify(http).addFilterAfter(any(MfaManagementFilter.class), eq(BearerTokenAuthenticationFilter.class));
    }

    @Test
    void skipsFiltersWhenNoMfaServicesAreConfigured() {
        HttpSecurity http = mock(HttpSecurity.class);
        var configurer = new MfaSecurityConfigurer(
                mock(AuthenticationManager.class),
                new MfaProperties(MfaProperties.Mfa.defaults(), null),
                JsonMapper.builder().build(),
                mock(MfaAwareLoginSuccessHandler.class),
                mock(AuthenticationFailureHandler.class),
                null,
                mock(MfaPolicyProvider.class),
                null,
                null,
                null,
                Clock.systemUTC());

        configurer.configure(http);

        org.mockito.Mockito.verifyNoInteractions(http);
    }
}

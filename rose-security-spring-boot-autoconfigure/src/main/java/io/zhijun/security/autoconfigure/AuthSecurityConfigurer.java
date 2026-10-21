package io.zhijun.security.autoconfigure;

import io.zhijun.security.core.UserSessionException;
import io.zhijun.security.core.UserSessionService;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import tools.jackson.databind.json.JsonMapper;

/** Filter integration for hosts that explicitly apply it to their own SecurityFilterChain. */
public final class AuthSecurityConfigurer extends AbstractHttpConfigurer<AuthSecurityConfigurer, HttpSecurity> {

    private final AuthenticationManager loginAuthenticationManager;
    private final UserSessionService userSessionService;
    private final AuthSecurityProperties properties;
    private final JsonMapper jsonMapper;
    private final AuthenticationSuccessHandler loginSuccessHandler;
    private final AuthenticationSuccessHandler refreshSuccessHandler;
    private final LogoutHandler logoutHandler;
    private final LogoutSuccessHandler logoutSuccessHandler;
    private final AuthenticationFailureHandler authenticationFailureHandler;

    public AuthSecurityConfigurer(
            AuthenticationManager loginAuthenticationManager,
            UserSessionService userSessionService,
            AuthSecurityProperties properties,
            JsonMapper jsonMapper,
            AuthenticationSuccessHandler loginSuccessHandler,
            AuthenticationSuccessHandler refreshSuccessHandler,
            LogoutHandler logoutHandler,
            LogoutSuccessHandler logoutSuccessHandler) {
        this(
                loginAuthenticationManager,
                userSessionService,
                properties,
                jsonMapper,
                loginSuccessHandler,
                refreshSuccessHandler,
                logoutHandler,
                logoutSuccessHandler,
                new AuthenticationEntryPointFailureHandler(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)));
    }

    public AuthSecurityConfigurer(
            AuthenticationManager loginAuthenticationManager,
            UserSessionService userSessionService,
            AuthSecurityProperties properties,
            JsonMapper jsonMapper,
            AuthenticationSuccessHandler loginSuccessHandler,
            AuthenticationSuccessHandler refreshSuccessHandler,
            LogoutHandler logoutHandler,
            LogoutSuccessHandler logoutSuccessHandler,
            AuthenticationFailureHandler authenticationFailureHandler) {
        this.loginAuthenticationManager = loginAuthenticationManager;
        this.userSessionService = userSessionService;
        this.properties = properties;
        this.jsonMapper = jsonMapper;
        this.loginSuccessHandler = loginSuccessHandler;
        this.refreshSuccessHandler = refreshSuccessHandler;
        this.logoutHandler = logoutHandler;
        this.logoutSuccessHandler = logoutSuccessHandler;
        this.authenticationFailureHandler = authenticationFailureHandler;
    }

    @Override
    public void init(HttpSecurity http) {
        AuthSecurityProperties.Endpoints endpoints = properties.endpoints();
        String logoutPath = path(endpoints, endpoints.logout());
        String logoutAllPath = path(endpoints, endpoints.logoutAll());
        http.logout(logout -> logout.logoutRequestMatcher(new OrRequestMatcher(post(logoutPath), post(logoutAllPath)))
                .addLogoutHandler(logoutHandler)
                .logoutSuccessHandler(logoutSuccessHandler));
    }

    @Override
    public void configure(HttpSecurity http) {
        AuthSecurityProperties.Endpoints endpoints = properties.endpoints();
        String loginPath = path(endpoints, endpoints.login());
        String refreshPath = path(endpoints, endpoints.refresh());
        AuthenticationFilter loginFilter =
                new AuthenticationFilter(loginAuthenticationManager, new JsonLoginAuthenticationConverter(jsonMapper));
        loginFilter.setRequestMatcher(post(loginPath));
        loginFilter.setSecurityContextRepository(new NullSecurityContextRepository());
        loginFilter.setSuccessHandler(loginSuccessHandler);
        loginFilter.setFailureHandler(authenticationFailureHandler);
        http.addFilterBefore(loginFilter, UsernamePasswordAuthenticationFilter.class);

        if (properties.jwt().refreshEnabled()) {
            AuthenticationManager refreshAuthenticationManager = authentication -> {
                if (!(authentication instanceof RefreshRequestAuthenticationToken refreshRequest)) {
                    throw new BadCredentialsException("Authentication failed");
                }
                try {
                    return RefreshRequestAuthenticationToken.authenticated(
                            userSessionService.refresh(refreshRequest.refreshToken()));
                } catch (UserSessionException exception) {
                    throw new BadCredentialsException("Authentication failed", exception);
                } catch (RuntimeException exception) {
                    throw new AuthenticationServiceException("Authentication could not be completed", exception);
                }
            };
            AuthenticationFilter refreshFilter = new AuthenticationFilter(
                    refreshAuthenticationManager, new JsonRefreshTokenAuthenticationConverter(jsonMapper));
            refreshFilter.setRequestMatcher(post(refreshPath));
            refreshFilter.setSecurityContextRepository(new NullSecurityContextRepository());
            refreshFilter.setSuccessHandler(refreshSuccessHandler);
            refreshFilter.setFailureHandler(authenticationFailureHandler);
            http.addFilterBefore(refreshFilter, UsernamePasswordAuthenticationFilter.class);
        }
    }

    private static RequestMatcher post(String path) {
        return request -> HttpMethod.POST.matches(request.getMethod()) && path.equals(request.getServletPath());
    }

    static String path(AuthSecurityProperties.Endpoints endpoints, String endpoint) {
        return endpoints.basePath().replaceAll("/$", "") + "/" + endpoint.replaceAll("^/", "");
    }
}

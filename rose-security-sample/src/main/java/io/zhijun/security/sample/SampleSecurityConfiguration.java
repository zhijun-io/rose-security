package io.zhijun.security.sample;

import io.zhijun.security.autoconfigure.AuthSecurityConfigurer;
import io.zhijun.security.autoconfigure.JwksEndpoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import tools.jackson.databind.json.JsonMapper;

/** Example host-owned chain. The starter does not create a catch-all chain. */
@Configuration(proxyBeanMethods = false)
public class SampleSecurityConfiguration {

    @Bean
    AuthenticationFailureHandler sampleAuthenticationFailureHandler(JsonMapper jsonMapper) {
        return (request, response, exception) -> {
            HttpStatus status = exception instanceof AuthenticationServiceException
                    ? HttpStatus.SERVICE_UNAVAILABLE
                    : HttpStatus.UNAUTHORIZED;
            response.setStatus(status.value());
            response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
            response.setHeader("Cache-Control", "no-store");
            response.setHeader("Pragma", "no-cache");
            jsonMapper.writeValue(
                    response.getOutputStream(), ProblemDetail.forStatusAndDetail(status, "Authentication failed"));
            response.flushBuffer();
        };
    }

    @Bean
    @Order(1)
    SecurityFilterChain sampleApiChain(HttpSecurity http, AuthSecurityConfigurer auth) throws Exception {
        return http.securityMatcher("/api/**", JwksEndpoint.PATH)
                .with(auth, Customizer.withDefaults())
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(
                                HttpMethod.POST,
                                "/api/auth/login",
                                "/api/auth/refresh",
                                "/api/auth/logout",
                                "/api/auth/logout-all")
                        .permitAll()
                        .requestMatchers(JwksEndpoint.PATH)
                        .permitAll()
                        .requestMatchers("/api/sample/health")
                        .permitAll()
                        .anyRequest()
                        .authenticated())
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()))
                // This sample API authenticates with Authorization headers and sends refresh
                // tokens in JSON bodies; it does not use browser cookies for authentication.
                .csrf(org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer::disable)
                .build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain denyUnconfiguredRoutes(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/", "/index.html", "/assets/**", "/favicon.ico", "/actuator/health")
                        .permitAll()
                        .anyRequest()
                        .denyAll())
                .build();
    }
}

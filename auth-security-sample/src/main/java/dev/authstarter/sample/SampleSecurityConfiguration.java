package dev.authstarter.sample;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/** Example host-owned chain. The starter does not create a catch-all chain. */
@Configuration(proxyBeanMethods = false)
public class SampleSecurityConfiguration {

    @Bean
    @Order(1)
    SecurityFilterChain sampleApiChain(HttpSecurity http) throws Exception {
        return http.securityMatcher("/api/**")
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/api/sample/health")
                        .permitAll()
                        .anyRequest()
                        .denyAll())
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

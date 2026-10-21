package io.zhijun.security.sample;

import io.zhijun.security.core.UserSecurityVersionProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Demo-only in-process identity setup; production applications own these integrations.
 */
@Configuration(proxyBeanMethods = false)
public class SampleAuthenticationConfiguration {

    @Bean
    PasswordEncoder samplePasswordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    UserDetailsService sampleUserDetailsService(PasswordEncoder passwordEncoder) {
        String demoUsername = "demo@example.test";
        String encodedPassword = passwordEncoder.encode("password");
        return username -> {
            if (!demoUsername.equals(username)) {
                throw new UsernameNotFoundException("User not found");
            }
            return User.withUsername(demoUsername)
                    .password(encodedPassword)
                    .authorities("ROLE_USER")
                    .build();
        };
    }

    @Bean
    UserSecurityVersionProvider sampleSecurityVersionProvider() {
        return username -> 0;
    }
}

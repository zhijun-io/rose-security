package dev.authstarter.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.web.SecurityFilterChain;

class AuthSecurityAutoConfigurationTests {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AuthSecurityAutoConfiguration.class));

    @Test
    void registersDefaultsWithoutTakingOverSecurityFilterChain() {
        contextRunner.run(context -> {
            assertThat(context).hasSingleBean(AuthSecurityProperties.class);
            assertThat(context).doesNotHaveBean(SecurityFilterChain.class);
            AuthSecurityProperties properties = context.getBean(AuthSecurityProperties.class);
            assertThat(properties.enabled()).isTrue();
            assertThat(properties.token().enabled()).isFalse();
            assertThat(properties.endpoints().basePath()).isEqualTo("/api/auth");
        });
    }

    @Test
    void canDisableAutoConfiguration() {
        contextRunner.withPropertyValues("auth.security.enabled=false").run(context -> {
            assertThat(context).doesNotHaveBean(AuthSecurityProperties.class);
        });
    }

    @Test
    void validatesTokenConfigurationWhenIssuanceIsEnabled() {
        contextRunner.withPropertyValues("auth.security.token.enabled=true").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .hasStackTraceContaining(
                            "Enabled token issuance requires issuer, audience, RS256 and a key provider");
        });
    }

    @Test
    void rejectsCollidingEndpointPaths() {
        contextRunner
                .withPropertyValues("auth.security.endpoints.login=/session", "auth.security.endpoints.logout=/session")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasStackTraceContaining(
                                    "Authentication endpoint paths must be absolute paths and must not collide");
                });
    }
}

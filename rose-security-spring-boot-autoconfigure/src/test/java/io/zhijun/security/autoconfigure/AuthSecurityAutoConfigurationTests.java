package io.zhijun.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.validation.autoconfigure.ValidationAutoConfiguration;
import org.springframework.security.web.SecurityFilterChain;

class AuthSecurityAutoConfigurationTests {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(
                    AutoConfigurations.of(AuthSecurityAutoConfiguration.class, ValidationAutoConfiguration.class))
            .withPropertyValues(
                    "auth.security.jwt.issuer=https://auth.example.test",
                    "auth.security.jwt.audience=sample-api");

    @Test
    void registersDefaultsWithoutTakingOverSecurityFilterChain() {
        contextRunner.run(context -> {
            assertThat(context).hasSingleBean(AuthSecurityProperties.class);
            assertThat(context).doesNotHaveBean(SecurityFilterChain.class);
            AuthSecurityProperties properties = context.getBean(AuthSecurityProperties.class);
            assertThat(properties.enabled()).isTrue();
            assertThat(properties.endpoints().basePath()).isEqualTo("/api/auth");
            assertThat(properties.sessionConcurrency().maximumActiveSessions()).isZero();
            assertThat(properties.sessionConcurrency().whenLimitReached())
                    .isEqualTo(io.zhijun.security.core.UserSessionConcurrencyPolicy.LimitBehavior.DENY_NEW);
            assertThat(properties.remoteLogin().enabled()).isFalse();
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
        contextRunner.withPropertyValues("auth.security.jwt.issuer=", "auth.security.jwt.audience=").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .hasStackTraceContaining("Enabled token issuance requires issuer and audience");
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

    @Test
    void bindsSessionConcurrencySettings() {
        contextRunner
                .withPropertyValues(
                        "auth.security.session-concurrency.maximum-active-sessions=3",
                        "auth.security.session-concurrency.when-limit-reached=revoke-oldest")
                .run(context -> {
                    AuthSecurityProperties.SessionConcurrency concurrency =
                            context.getBean(AuthSecurityProperties.class).sessionConcurrency();
                    assertThat(concurrency.maximumActiveSessions()).isEqualTo(3);
                    assertThat(concurrency.whenLimitReached())
                            .isEqualTo(
                                    io.zhijun.security.core.UserSessionConcurrencyPolicy.LimitBehavior.REVOKE_OLDEST);
                });
    }
}

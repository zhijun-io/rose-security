package io.zhijun.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.validation.autoconfigure.ValidationAutoConfiguration;
import org.springframework.context.annotation.Configuration;

class MfaPropertiesTests {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(PropertiesConfiguration.class)
            .withConfiguration(AutoConfigurations.of(ValidationAutoConfiguration.class));

    @Test
    void keepsExistingMfaPropertyKeysAndDefaultsDisabled() {
        contextRunner
                .withPropertyValues(
                        "auth.security.mfa.enabled=true",
                        "auth.security.mfa.methods[0]=totp",
                        "auth.security.mfa.transaction-ttl=3m",
                        "auth.security.mfa.maximum-attempts=4",
                        "auth.security.endpoints.mfa-verify=/factor/check")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    MfaProperties properties = context.getBean(MfaProperties.class);
                    assertThat(properties.mfa().enabled()).isTrue();
                    assertThat(properties.mfa().methods()).containsExactly("totp");
                    assertThat(properties.mfa().transactionTtl()).isEqualTo(java.time.Duration.ofMinutes(3));
                    assertThat(properties.mfa().maximumAttempts()).isEqualTo(4);
                    assertThat(properties.endpoints().mfaVerify()).isEqualTo("/factor/check");
                });
    }

    @Test
    void mfaIsDisabledByDefault() {
        contextRunner.run(context ->
                assertThat(context.getBean(MfaProperties.class).mfa().enabled()).isFalse());
    }

    @Test
    void configuredWebAuthnRequiresDeploymentConfigurationEvenWhenDefaultPolicyIsDisabled() {
        contextRunner
                .withPropertyValues("auth.security.mfa.methods[0]=webauthn")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasStackTraceContaining("WebAuthn MFA requires an RP ID and at least one allowed origin");
                });
    }

    @Test
    void rejectsMfaPathCollidingWithAuthenticationEndpoint() {
        contextRunner
                .withPropertyValues("auth.security.endpoints.me-mfa=/api/auth/login")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasStackTraceContaining("MFA endpoint paths must be absolute paths and must not collide");
                });
    }

    @Test
    void enabledFactorWithoutRequiredServiceFailsClosed() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(MfaAutoConfiguration.class, ValidationAutoConfiguration.class))
                .withPropertyValues("auth.security.mfa.enabled=true", "auth.security.mfa.methods[0]=totp")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasStackTraceContaining("MFA method 'totp' is enabled but its service");
                });
    }

    @Test
    void defaultPolicyRejectsUnimplementedFactorNames() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(MfaAutoConfiguration.class, ValidationAutoConfiguration.class))
                .withPropertyValues("auth.security.mfa.enabled=true", "auth.security.mfa.methods[0]=wallet")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasStackTraceContaining("not supported by the default policy provider");
                });
    }

    @Test
    void mfaModuleDoesNotRequireBaseAuthenticationBeansByItself() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(MfaAutoConfiguration.class))
                .withConfiguration(AutoConfigurations.of(ValidationAutoConfiguration.class))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(MfaAwareLoginSuccessHandler.class);
                    assertThat(context).doesNotHaveBean(MfaSecurityConfigurer.class);
                });
    }

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(MfaProperties.class)
    static class PropertiesConfiguration {}
}

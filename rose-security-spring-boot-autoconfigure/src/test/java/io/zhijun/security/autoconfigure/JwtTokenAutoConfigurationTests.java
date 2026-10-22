package io.zhijun.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.zhijun.security.core.IssuedAccessToken;
import io.zhijun.security.core.IssuedSessionTokens;
import io.zhijun.security.core.JwtTokenIssuer;
import io.zhijun.security.core.UserSessionClientInfo;
import io.zhijun.security.core.UserSessionService;
import io.zhijun.security.core.UserSessionView;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtException;

class JwtTokenAutoConfigurationTests {

    @TempDir
    Path tempDir;

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(
                    AutoConfigurations.of(AuthSecurityAutoConfiguration.class, JwtTokenAutoConfiguration.class));

    @Test
    void doesNotCreateJwksEndpointWhenHostProvidesJwtCodecWithoutJwkSource() {
        contextRunner
                .withBean(JwtEncoder.class, () -> parameters -> null)
                .withBean(JwtDecoder.class, () -> token -> null)
                .withBean(UserSessionService.class, NoopUserSessionService::new)
                .withPropertyValues(
                        "auth.security.jwt.issuer=https://auth.example.test", "auth.security.jwt.audience=sample-api")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(JwksEndpoint.class);
                });
    }

    @Test
    void sharedStarterSwitchDisablesTokenBeans() {
        contextRunner
                .withPropertyValues(
                        "auth.security.enabled=false",
                        "auth.security.jwt.issuer=https://auth.example.test",
                        "auth.security.jwt.audience=sample-api")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(JwtTokenIssuer.class);
                    assertThat(context).doesNotHaveBean(JwtDecoder.class);
                });
    }

    @Test
    void issuesAndValidatesRs256TokensWithIssuerAudienceAndSecurityClaims() throws Exception {
        JWKSource<SecurityContext> jwkSource = testJwkSource();
        contextRunner
                .withBean(JWKSource.class, () -> jwkSource)
                .withBean(UserSessionService.class, NoopUserSessionService::new)
                .withPropertyValues(
                        "auth.security.jwt.issuer=https://auth.example.test", "auth.security.jwt.audience=sample-api")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    JwtTokenIssuer issuer = context.getBean(JwtTokenIssuer.class);
                    JwtDecoder decoder = context.getBean(JwtDecoder.class);
                    Instant authenticatedAt = Instant.now().minusSeconds(5);
                    IssuedAccessToken issued = issuer.issue(
                            User.withUsername("person@example.test")
                                    .password("not-used")
                                    .authorities("ROLE_USER")
                                    .build(),
                            "session-9",
                            List.of("pwd"),
                            authenticatedAt,
                            3);

                    var decoded = decoder.decode(issued.value());
                    assertThat(decoded.getSubject()).isEqualTo("person@example.test");
                    assertThat(decoded.getHeaders().get("kid")).isEqualTo("test-key-1");
                    assertThat(decoded.getAudience()).containsExactly("sample-api");
                    assertThat(decoded.getClaimAsString("sid")).isEqualTo("session-9");
                    assertThat(((Number) decoded.getClaim("security_version")).longValue())
                            .isEqualTo(3L);
                    assertThat(decoded.getClaimAsStringList("amr")).containsExactly("pwd");
                    assertThat(issued.expiresAt()).isEqualTo(decoded.getExpiresAt());
                    assertThat(issued.toString()).doesNotContain(issued.value());
                });
    }

    @Test
    void publishesOnlyPublicJwksAndSignsWithConfiguredActiveKeyId() throws Exception {
        JWKSource<SecurityContext> jwkSource = testJwkSource("old-key", "current-key");
        contextRunner
                .withBean(JWKSource.class, () -> jwkSource)
                .withBean(UserSessionService.class, NoopUserSessionService::new)
                .withPropertyValues(
                        "auth.security.jwt.issuer=https://auth.example.test",
                        "auth.security.jwt.audience=sample-api",
                        "auth.security.jwt.active-key-id=current-key")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    var jwks = context.getBean(JwksEndpoint.class).getJwks();
                    @SuppressWarnings("unchecked")
                    List<java.util.Map<String, Object>> keys = (List<java.util.Map<String, Object>>) jwks.get("keys");
                    assertThat(keys).hasSize(2);
                    assertThat(keys)
                            .extracting(key -> key.get("kid"))
                            .containsExactlyInAnyOrder("old-key", "current-key");
                    assertThat(keys).allSatisfy(key -> assertThat(key).doesNotContainKey("d"));

                    IssuedAccessToken issued = context.getBean(JwtTokenIssuer.class)
                            .issue(
                                    User.withUsername("person@example.test")
                                            .password("unused")
                                            .authorities("ROLE_USER")
                                            .build(),
                                    "session-1",
                                    List.of("pwd"),
                                    Instant.now().minusSeconds(2),
                                    1);
                    assertThat(context.getBean(JwtDecoder.class)
                                    .decode(issued.value())
                                    .getHeaders()
                                    .get("kid"))
                            .isEqualTo("current-key");
                });
    }

    @Test
    void requiresActiveKeyIdWhenMultipleSigningKeysAreConfigured() {
        contextRunner
                .withBean(JWKSource.class, () -> testJwkSource("first-key", "second-key"))
                .withBean(UserSessionService.class, NoopUserSessionService::new)
                .withPropertyValues(
                        "auth.security.jwt.issuer=https://auth.example.test", "auth.security.jwt.audience=sample-api")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasStackTraceContaining("Multiple signing keys require auth.security.jwt.active-key-id");
                });
    }

    @Test
    void loadsDefaultNimbusKeysFromConfiguredPemFiles() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        Path privateKeyFile = tempDir.resolve("jwt-private.pem");
        Path publicKeyFile = tempDir.resolve("jwt-public.pem");
        Files.writeString(privateKeyFile, pem("PRIVATE KEY", pair.getPrivate().getEncoded()));
        Files.writeString(publicKeyFile, pem("PUBLIC KEY", pair.getPublic().getEncoded()));

        contextRunner
                .withBean(UserSessionService.class, NoopUserSessionService::new)
                .withPropertyValues(
                        "auth.security.jwt.issuer=https://auth.example.test",
                        "auth.security.jwt.audience=sample-api",
                        "auth.security.jwt.private-key-file=" + privateKeyFile,
                        "auth.security.jwt.public-key-file=" + publicKeyFile)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(JWKSource.class);
                    assertThat(context).hasSingleBean(JwtEncoder.class);
                    assertThat(context).hasSingleBean(JwtDecoder.class);
                    IssuedAccessToken issued = context.getBean(JwtTokenIssuer.class)
                            .issue(
                                    User.withUsername("pem@example.test")
                                            .password("unused")
                                            .authorities("ROLE_USER")
                                            .build(),
                                    "pem-session",
                                    List.of("pwd"),
                                    Instant.now().minusSeconds(5),
                                    1);
                    assertThat(context.getBean(JwtDecoder.class)
                                    .decode(issued.value())
                                    .getSubject())
                            .isEqualTo("pem@example.test");
                });
    }

    @Test
    void prefersHostJwkSourceWhenPemFilePropertiesAreAlsoConfigured() {
        JWKSource<SecurityContext> jwkSource = testJwkSource();
        contextRunner
                .withBean(JWKSource.class, () -> jwkSource)
                .withBean(UserSessionService.class, NoopUserSessionService::new)
                .withPropertyValues(
                        "auth.security.jwt.issuer=https://auth.example.test",
                        "auth.security.jwt.audience=sample-api",
                        "auth.security.jwt.private-key-file=/missing/private.pem",
                        "auth.security.jwt.public-key-file=/missing/public.pem")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(JWKSource.class)).isSameAs(jwkSource);
                });
    }

    @Test
    void requiresBothPemKeyFileLocations() {
        contextRunner
                .withPropertyValues(
                        "auth.security.jwt.issuer=https://auth.example.test",
                        "auth.security.jwt.audience=sample-api",
                        "auth.security.jwt.private-key-file=/run/secrets/jwt-private.pem")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasStackTraceContaining(
                                    "JWT private-key-file and public-key-file must be configured together");
                });
    }

    @Test
    void usesHostProvidedClockForTokenTimes() {
        Instant fixedTime = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        Clock fixedClock = Clock.fixed(fixedTime, ZoneOffset.UTC);
        JWKSource<SecurityContext> jwkSource = testJwkSource();
        contextRunner
                .withBean(JWKSource.class, () -> jwkSource)
                .withBean(UserSessionService.class, NoopUserSessionService::new)
                .withBean(Clock.class, () -> fixedClock)
                .withPropertyValues(
                        "auth.security.jwt.issuer=https://auth.example.test", "auth.security.jwt.audience=sample-api")
                .run(context -> {
                    JwtTokenIssuer issuer = context.getBean(JwtTokenIssuer.class);
                    IssuedAccessToken token = issuer.issue(
                            User.withUsername("person@example.test")
                                    .password("unused")
                                    .authorities("ROLE_USER")
                                    .build(),
                            "session-10",
                            List.of("pwd"),
                            fixedTime.minusSeconds(5),
                            1);

                    assertThat(token.issuedAt()).isEqualTo(fixedTime);
                    assertThat(context.getBean(Clock.class)).isSameAs(fixedClock);
                });
    }

    @Test
    void rejectsTokensWithAnUnexpectedAudience() {
        JWKSource<SecurityContext> jwkSource = testJwkSource();
        contextRunner
                .withBean(JWKSource.class, () -> jwkSource)
                .withBean(UserSessionService.class, NoopUserSessionService::new)
                .withPropertyValues(
                        "auth.security.jwt.issuer=https://auth.example.test", "auth.security.jwt.audience=sample-api")
                .run(context -> {
                    JwtEncoder encoder = context.getBean(JwtEncoder.class);
                    JwtDecoder decoder = context.getBean(JwtDecoder.class);
                    Instant now = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
                    String wrongAudienceToken = encoder.encode(JwtEncoderParameters.from(
                                    JwsHeader.with(SignatureAlgorithm.RS256)
                                            .keyId("test-key-1")
                                            .build(),
                                    JwtClaimsSet.builder()
                                            .issuer("https://auth.example.test")
                                            .audience(List.of("another-api"))
                                            .subject("person@example.test")
                                            .issuedAt(now)
                                            .notBefore(now)
                                            .expiresAt(now.plusSeconds(60))
                                            .build()))
                            .getTokenValue();

                    assertThatThrownBy(() -> decoder.decode(wrongAudienceToken)).isInstanceOf(JwtException.class);
                });
    }

    private static JWKSource<SecurityContext> testJwkSource() {
        return testJwkSource("test-key-1");
    }

    private static JWKSource<SecurityContext> testJwkSource(String... keyIds) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            List<JWK> keys = new java.util.ArrayList<>();
            for (String keyId : keyIds) {
                KeyPair pair = generator.generateKeyPair();
                keys.add(new RSAKey.Builder((RSAPublicKey) pair.getPublic())
                        .privateKey((RSAPrivateKey) pair.getPrivate())
                        .keyID(keyId)
                        .algorithm(JWSAlgorithm.RS256)
                        .keyUse(KeyUse.SIGNATURE)
                        .build());
            }
            JWKSet jwkSet = new JWKSet(keys);
            return (selector, context) -> selector.select(jwkSet);
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }

    private static String pem(String label, byte[] encoded) {
        String body = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(encoded);
        return "-----BEGIN " + label + "-----\n" + body + "\n-----END " + label + "-----\n";
    }

    private static final class NoopUserSessionService implements UserSessionService {

        @Override
        public IssuedSessionTokens create(
                UserDetails principal,
                java.util.Collection<String> authenticationMethods,
                Instant authenticatedAt,
                UserSessionClientInfo clientInfo) {
            throw new UnsupportedOperationException();
        }

        @Override
        public IssuedSessionTokens refresh(String refreshToken) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean revoke(String username, String sessionId) {
            return false;
        }

        @Override
        public int revokeAll(String username) {
            return 0;
        }

        @Override
        public List<UserSessionView> findActiveSessions(String username) {
            return List.of();
        }
    }
}

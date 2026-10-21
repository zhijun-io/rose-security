package io.zhijun.security.autoconfigure;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.zhijun.security.core.JwtTokenIssuer;
import io.zhijun.security.core.UserSecurityVersionProvider;
import io.zhijun.security.core.UserSessionConcurrencyPolicy;
import io.zhijun.security.core.UserSessionService;
import io.zhijun.security.core.UserSessionStore;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.util.List;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

/** Configures Spring Security's Nimbus JWT encoder and decoder while the starter is enabled. */
@AutoConfiguration(after = AuthSecurityAutoConfiguration.class)
@ConditionalOnProperty(prefix = "auth.security", name = "enabled", havingValue = "true", matchIfMissing = true)
public class JwtTokenAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(Clock.class)
    Clock authSecurityClock() {
        return Clock.systemUTC();
    }

    @Bean
    @ConditionalOnMissingBean(JWKSource.class)
    @ConditionalOnProperty(
            prefix = "auth.security.jwt",
            name = {"private-key-file", "public-key-file"})
    JWKSource<SecurityContext> authSecurityJwkSource(AuthSecurityProperties properties) {
        AuthSecurityProperties.Jwt token = properties.jwt();
        try {
            RSAPrivateKey privateKey = readPrivateKey(token.privateKeyFile());
            RSAPublicKey publicKey = readPublicKey(token.publicKeyFile());
            if (publicKey.getModulus().bitLength() < 2048 || !matches(privateKey, publicKey)) {
                throw new IllegalStateException(
                        "Configured JWT RSA key files are not a matching pair of at least 2048 bits");
            }
            String keyId = token.activeKeyId() == null ? defaultKeyId(publicKey) : token.activeKeyId();
            JWKSet keys = new JWKSet(new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(keyId)
                    .algorithm(JWSAlgorithm.RS256)
                    .keyUse(KeyUse.SIGNATURE)
                    .build());
            return (selector, context) -> selector.select(keys);
        } catch (IOException | GeneralSecurityException | IllegalArgumentException exception) {
            throw new IllegalStateException("Could not load configured JWT RSA key files", exception);
        }
    }

    @Bean
    @ConditionalOnMissingBean(JwtEncoder.class)
    JwtEncoder authSecurityJwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    @ConditionalOnMissingBean(JwtDecoder.class)
    JwtDecoder authSecurityJwtDecoder(JWKSource<SecurityContext> jwkSource, AuthSecurityProperties properties) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSource(jwkSource)
                .jwsAlgorithm(SignatureAlgorithm.RS256)
                .build();
        OAuth2TokenValidator<Jwt> audienceValidator =
                jwt -> jwt.getAudience().contains(properties.jwt().audience())
                        ? OAuth2TokenValidatorResult.success()
                        : OAuth2TokenValidatorResult.failure(
                                new OAuth2Error("invalid_token", "The required audience is missing", null));
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(properties.jwt().issuer()), audienceValidator));
        return decoder;
    }

    @Bean
    @ConditionalOnMissingBean(JwtTokenIssuer.class)
    JwtTokenIssuer authSecurityJwtTokenIssuer(
            JwtEncoder jwtEncoder,
            org.springframework.beans.factory.ObjectProvider<JWKSource<SecurityContext>> jwkSources,
            AuthSecurityProperties properties,
            Clock clock) {
        String activeKeyId = properties.jwt().activeKeyId();
        if (activeKeyId == null) {
            activeKeyId = singleSigningKeyId(jwkSources.getIfAvailable());
        }
        return new JwtTokenIssuerImpl(jwtEncoder, properties, clock, activeKeyId);
    }

    @Bean
    @ConditionalOnMissingBean(JwksEndpoint.class)
    @ConditionalOnBean(JWKSource.class)
    @ConditionalOnClass(org.springframework.web.bind.annotation.RestController.class)
    JwksEndpoint authSecurityJwksEndpoint(JWKSource<SecurityContext> jwkSource) {
        return new JwksEndpoint(jwkSource);
    }

    @Bean
    @ConditionalOnMissingBean(UserSessionService.class)
    UserSessionService authSecurityUserSessionService(
            JwtTokenIssuer jwtTokenIssuer,
            UserSessionStore userSessionStore,
            UserDetailsService userDetailsService,
            UserSecurityVersionProvider securityVersionProvider,
            UserSessionConcurrencyPolicy concurrencyPolicy,
            AuthSecurityProperties properties,
            Clock clock) {
        return new RefreshUserSessionService(
                jwtTokenIssuer,
                userSessionStore,
                userDetailsService,
                securityVersionProvider,
                concurrencyPolicy,
                properties,
                clock,
                new SecureRandom());
    }

    private static RSAPrivateKey readPrivateKey(String location) throws IOException {
        try (InputStream input = Files.newInputStream(absolutePath(location, "private-key-file"))) {
            return RsaKeyConverters.pkcs8().convert(input);
        }
    }

    private static RSAPublicKey readPublicKey(String location) throws IOException {
        try (InputStream input = Files.newInputStream(absolutePath(location, "public-key-file"))) {
            return RsaKeyConverters.x509().convert(input);
        }
    }

    private static Path absolutePath(String location, String propertyName) {
        Path path = Path.of(location);
        if (!path.isAbsolute()) {
            throw new IllegalStateException("JWT " + propertyName + " must be an absolute file path");
        }
        return path;
    }

    private static boolean matches(RSAPrivateKey privateKey, RSAPublicKey publicKey) throws GeneralSecurityException {
        byte[] challenge = "rose-security-rsa-key-pair-check".getBytes(StandardCharsets.UTF_8);
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(challenge);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(challenge);
        return verifier.verify(signature);
    }

    private static String defaultKeyId(RSAPublicKey publicKey) {
        try {
            byte[] fingerprint =
                    java.security.MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded());
            return java.util.HexFormat.of().formatHex(fingerprint, 0, 8);
        } catch (java.security.NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required for JWT key identifiers", exception);
        }
    }

    private static String singleSigningKeyId(JWKSource<SecurityContext> jwkSource) {
        if (jwkSource == null) {
            return null;
        }
        try {
            List<JWK> signingKeys =
                    jwkSource
                            .get(
                                    new JWKSelector(new JWKMatcher.Builder()
                                            .keyType(KeyType.RSA)
                                            .build()),
                                    null)
                            .stream()
                            .filter(JWK::isPrivate)
                            .filter(key -> key.getKeyUse() == null || KeyUse.SIGNATURE.equals(key.getKeyUse()))
                            .filter(key -> key.getAlgorithm() == null || JWSAlgorithm.RS256.equals(key.getAlgorithm()))
                            .toList();
            if (signingKeys.size() > 1) {
                throw new IllegalStateException(
                        "Multiple signing keys require auth.security.jwt.active-key-id to select the current key");
            }
            return signingKeys.isEmpty() ? null : signingKeys.getFirst().getKeyID();
        } catch (KeySourceException exception) {
            throw new IllegalStateException("Could not select the active JWT signing key", exception);
        }
    }
}

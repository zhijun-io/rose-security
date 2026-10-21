package io.zhijun.security.autoconfigure;

import io.zhijun.security.core.IssuedAccessToken;
import io.zhijun.security.core.JwtTokenIssuer;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;

final class JwtTokenIssuerImpl implements JwtTokenIssuer {

    private final JwtEncoder jwtEncoder;
    private final AuthSecurityProperties properties;
    private final Clock clock;
    private final String activeKeyId;

    JwtTokenIssuerImpl(JwtEncoder jwtEncoder, AuthSecurityProperties properties, Clock clock, String activeKeyId) {
        this.jwtEncoder = jwtEncoder;
        this.properties = properties;
        this.clock = clock;
        this.activeKeyId = activeKeyId;
    }

    @Override
    public IssuedAccessToken issue(
            UserDetails principal,
            String sessionId,
            Collection<String> authenticationMethods,
            Instant authenticatedAt,
            long securityVersion) {
        if (principal == null
                || principal.getUsername() == null
                || principal.getUsername().isBlank()) {
            throw new IllegalArgumentException("A UserDetails principal with a username is required");
        }
        if (sessionId == null || sessionId.isBlank()) {
            throw new IllegalArgumentException("sessionId must not be blank");
        }
        if (authenticationMethods == null || authenticationMethods.isEmpty()) {
            throw new IllegalArgumentException("At least one authentication method is required");
        }
        if (securityVersion < 0) {
            throw new IllegalArgumentException("securityVersion must not be negative");
        }
        Instant issuedAt = clock.instant().truncatedTo(ChronoUnit.SECONDS);
        Instant expiresAt = issuedAt.plus(properties.jwt().accessTtl()).truncatedTo(ChronoUnit.SECONDS);
        JwsHeader.Builder headerBuilder =
                JwsHeader.with(SignatureAlgorithm.RS256).type("JWT");
        if (activeKeyId != null) {
            headerBuilder.keyId(activeKeyId);
        }
        JwsHeader headers = headerBuilder.build();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(properties.jwt().issuer())
                .audience(List.of(properties.jwt().audience()))
                .subject(principal.getUsername())
                .issuedAt(issuedAt)
                .notBefore(issuedAt)
                .expiresAt(expiresAt)
                .id(UUID.randomUUID().toString())
                .claim("sid", sessionId)
                .claim("security_version", securityVersion)
                .claim("auth_time", authenticatedAt.getEpochSecond())
                .claim("amr", List.copyOf(authenticationMethods))
                .build();

        String value =
                jwtEncoder.encode(JwtEncoderParameters.from(headers, claims)).getTokenValue();
        return new IssuedAccessToken(value, issuedAt, expiresAt);
    }
}

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
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Publishes verification keys at the well-known JWKS path without exposing private key material. */
@RestController
public class JwksEndpoint {

    public static final String PATH = "/.well-known/jwks.json";

    private final JWKSource<SecurityContext> jwkSource;

    public JwksEndpoint(JWKSource<SecurityContext> jwkSource) {
        this.jwkSource = jwkSource;
    }

    @GetMapping(value = PATH, produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> getJwks() {
        try {
            List<JWK> keys =
                    jwkSource
                            .get(
                                    new JWKSelector(new JWKMatcher.Builder()
                                            .keyType(KeyType.RSA)
                                            .build()),
                                    null)
                            .stream()
                            .filter(JwksEndpoint::isSigningKey)
                            .map(JWK::toPublicJWK)
                            .toList();
            requireUniqueKeyIdsForRotation(keys);
            return new JWKSet(keys).toJSONObject();
        } catch (KeySourceException exception) {
            throw new IllegalStateException("Could not load public JWT verification keys", exception);
        }
    }

    private static boolean isSigningKey(JWK key) {
        return key instanceof RSAKey
                && (key.getKeyUse() == null || KeyUse.SIGNATURE.equals(key.getKeyUse()))
                && (key.getAlgorithm() == null || JWSAlgorithm.RS256.equals(key.getAlgorithm()));
    }

    private static void requireUniqueKeyIdsForRotation(List<JWK> keys) {
        if (keys.size() < 2) {
            return;
        }
        Set<String> keyIds = keys.stream().map(JWK::getKeyID).collect(Collectors.toSet());
        if (keyIds.size() != keys.size() || keyIds.contains(null) || keyIds.contains("")) {
            throw new IllegalStateException("Multiple published JWT keys must each have a unique kid");
        }
    }
}

package io.zhijun.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import io.zhijun.security.core.WebAuthnMfaChallenge;
import io.zhijun.security.core.WebAuthnMfaChallengeStore;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRpEntity;
import org.springframework.security.web.webauthn.api.UserVerificationRequirement;
import org.springframework.security.web.webauthn.jackson.WebauthnJacksonModule;
import org.springframework.security.web.webauthn.management.MapPublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.MapUserCredentialRepository;
import org.springframework.security.web.webauthn.management.Webauthn4JRelyingPartyOperations;
import tools.jackson.databind.json.JsonMapper;

class WebAuthnMfaServiceTests {

    @Test
    void registrationOptionsRequireUserVerificationAndUseWebAuthnJsonEncoding() {
        var users = new MapPublicKeyCredentialUserEntityRepository();
        var credentials = new MapUserCredentialRepository();
        var relyingParty = new Webauthn4JRelyingPartyOperations(
                users,
                credentials,
                PublicKeyCredentialRpEntity.builder()
                        .id("example.test")
                        .name("Example")
                        .build(),
                Set.of("https://example.test"));
        var mapper = JsonMapper.builder().build();
        var service = new WebAuthnMfaService(
                relyingParty,
                users,
                credentials,
                new InMemoryChallenges(),
                mapper,
                new SecureRandom(),
                Duration.ofMinutes(5));

        var challenge = service.beginRegistration("user@example.test", Instant.parse("2026-10-22T00:00:00Z"));
        var options = (PublicKeyCredentialCreationOptions) challenge.publicKey();
        String json =
                mapper.rebuild().addModule(new WebauthnJacksonModule()).build().writeValueAsString(options);

        assertThat(options.getAuthenticatorSelection().getUserVerification())
                .isEqualTo(UserVerificationRequirement.REQUIRED);
        assertThat(json).contains("\"challenge\":\"").doesNotContain("\"challenge\":{");
        assertThat(challenge.challengeToken()).isNotBlank();
    }

    private static final class InMemoryChallenges implements WebAuthnMfaChallengeStore {

        private final Map<String, WebAuthnMfaChallenge> values = new HashMap<>();

        @Override
        public void save(String tokenHash, WebAuthnMfaChallenge challenge) {
            values.put(tokenHash, challenge);
        }

        @Override
        public Optional<WebAuthnMfaChallenge> consume(
                String tokenHash, String username, String operation, String transactionTokenHash, Instant now) {
            WebAuthnMfaChallenge value = values.get(tokenHash);
            if (value == null
                    || !value.username().equals(username)
                    || !value.operation().equals(operation)
                    || !java.util.Objects.equals(value.transactionTokenHash(), transactionTokenHash)) {
                return Optional.empty();
            }
            values.remove(tokenHash);
            return value.expiresAt().isAfter(now) ? Optional.of(value) : Optional.empty();
        }
    }
}

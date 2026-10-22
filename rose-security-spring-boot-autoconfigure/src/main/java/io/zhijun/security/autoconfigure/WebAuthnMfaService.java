package io.zhijun.security.autoconfigure;

import com.webauthn4j.verifier.exception.VerificationException;
import io.zhijun.security.core.WebAuthnMfaChallenge;
import io.zhijun.security.core.WebAuthnMfaChallengeStore;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.webauthn.api.AuthenticatorAssertionResponse;
import org.springframework.security.web.webauthn.api.AuthenticatorAttestationResponse;
import org.springframework.security.web.webauthn.api.AuthenticatorSelectionCriteria;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.api.PublicKeyCredential;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialDescriptor;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialType;
import org.springframework.security.web.webauthn.api.UserVerificationRequirement;
import org.springframework.security.web.webauthn.jackson.WebauthnJacksonModule;
import org.springframework.security.web.webauthn.management.ImmutablePublicKeyCredentialCreationOptionsRequest;
import org.springframework.security.web.webauthn.management.ImmutablePublicKeyCredentialRequestOptionsRequest;
import org.springframework.security.web.webauthn.management.ImmutableRelyingPartyRegistrationRequest;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.RelyingPartyAuthenticationRequest;
import org.springframework.security.web.webauthn.management.RelyingPartyPublicKey;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.security.web.webauthn.management.WebAuthnRelyingPartyOperations;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;

/** Uses Spring Security's WebAuthn operations with opaque, one-time MFA ceremony state. */
public class WebAuthnMfaService {

    private static final String LOGIN = "login";
    private static final String REGISTRATION = "registration";
    private static final String REMOVAL = "removal";

    private final WebAuthnRelyingPartyOperations relyingParty;
    private final PublicKeyCredentialUserEntityRepository users;
    private final UserCredentialRepository credentials;
    private final WebAuthnMfaChallengeStore challenges;
    private final JsonMapper mapper;
    private final SecureRandom random;
    private final Duration challengeTtl;

    public WebAuthnMfaService(
            WebAuthnRelyingPartyOperations relyingParty,
            PublicKeyCredentialUserEntityRepository users,
            UserCredentialRepository credentials,
            WebAuthnMfaChallengeStore challenges,
            JsonMapper mapper,
            SecureRandom random,
            Duration challengeTtl) {
        this.relyingParty = Objects.requireNonNull(relyingParty);
        this.users = Objects.requireNonNull(users);
        this.credentials = Objects.requireNonNull(credentials);
        this.challenges = Objects.requireNonNull(challenges);
        this.mapper = Objects.requireNonNull(mapper)
                .rebuild()
                .addModule(new WebauthnJacksonModule())
                .build();
        this.random = Objects.requireNonNull(random);
        this.challengeTtl = Objects.requireNonNull(challengeTtl);
    }

    public boolean isEnrolled(String username) {
        var user = users.findByUsername(username);
        return user != null && !credentials.findByUserId(user.getId()).isEmpty();
    }

    public List<Credential> credentials(String username) {
        var user = users.findByUsername(username);
        if (user == null) return List.of();
        return credentials.findByUserId(user.getId()).stream()
                .map(record -> new Credential(record.getCredentialId().toBase64UrlString(), record.getLabel()))
                .toList();
    }

    public StartedChallenge beginRegistration(String username, Instant now) {
        Authentication authentication = authentication(username);
        PublicKeyCredentialCreationOptions options =
                requireUserVerification(relyingParty.createPublicKeyCredentialCreationOptions(
                        new ImmutablePublicKeyCredentialCreationOptionsRequest(authentication)));
        String token = storeChallenge(username, REGISTRATION, null, options, now);
        return new StartedChallenge(token, options, now.plus(challengeTtl));
    }

    public void completeRegistration(String username, String challengeToken, RegistrationProof proof, Instant now) {
        PublicKeyCredentialCreationOptions options = consumeOptions(
                username, REGISTRATION, challengeToken, null, PublicKeyCredentialCreationOptions.class, now);
        try {
            if (proof == null
                    || proof.credential() == null
                    || proof.label() == null
                    || proof.label().isBlank()) {
                throw new BadCredentialsException("Authentication failed");
            }
            relyingParty.registerCredential(new ImmutableRelyingPartyRegistrationRequest(
                    options, new RelyingPartyPublicKey(proof.credential(), proof.label())));
        } catch (VerificationException | IllegalArgumentException exception) {
            throw new BadCredentialsException("Authentication failed", exception);
        }
    }

    public StartedChallenge beginLogin(String username, String loginTransactionToken, Instant now) {
        Authentication authentication = authentication(username);
        PublicKeyCredentialRequestOptions options = requireUserVerification(relyingParty.createCredentialRequestOptions(
                new ImmutablePublicKeyCredentialRequestOptionsRequest(authentication)));
        String transactionHash = hash(loginTransactionToken);
        String token = storeChallenge(username, LOGIN, transactionHash, options, now);
        return new StartedChallenge(token, options, now.plus(challengeTtl));
    }

    public boolean verifyLogin(String username, String loginTransactionToken, String proof, Instant now) {
        LoginProof submitted;
        try {
            submitted = mapper.readValue(proof, LoginProof.class);
        } catch (RuntimeException exception) {
            return false;
        }
        if (submitted == null || submitted.challengeToken() == null || submitted.credential() == null) return false;
        PublicKeyCredentialRequestOptions options;
        try {
            options = consumeOptions(
                    username,
                    LOGIN,
                    submitted.challengeToken(),
                    hash(loginTransactionToken),
                    PublicKeyCredentialRequestOptions.class,
                    now);
        } catch (BadCredentialsException exception) {
            return false;
        }
        try {
            var user =
                    relyingParty.authenticate(new RelyingPartyAuthenticationRequest(options, submitted.credential()));
            return user != null && username.equals(user.getName());
        } catch (VerificationException | IllegalArgumentException exception) {
            return false;
        }
    }

    public StartedChallenge beginRemoval(String username, String credentialId, Instant now) {
        if (credentialId == null || credentialId.isBlank()) {
            throw new BadCredentialsException("Authentication failed");
        }
        var user = users.findByUsername(username);
        CredentialRecord credential = credentials.findByCredentialId(
                org.springframework.security.web.webauthn.api.Bytes.fromBase64(credentialId));
        if (user == null
                || credential == null
                || !credential.getUserEntityUserId().equals(user.getId())) {
            throw new BadCredentialsException("Authentication failed");
        }
        Authentication authentication = authentication(username);
        PublicKeyCredentialRequestOptions base = relyingParty.createCredentialRequestOptions(
                new ImmutablePublicKeyCredentialRequestOptionsRequest(authentication));
        PublicKeyCredentialDescriptor allowedCredential = PublicKeyCredentialDescriptor.builder()
                .id(credential.getCredentialId())
                .type(PublicKeyCredentialType.PUBLIC_KEY)
                .transports(credential.getTransports())
                .build();
        PublicKeyCredentialRequestOptions options = PublicKeyCredentialRequestOptions.builder()
                .challenge(base.getChallenge())
                .timeout(base.getTimeout())
                .rpId(base.getRpId())
                .allowCredentials(List.of(allowedCredential))
                .extensions(base.getExtensions())
                .userVerification(UserVerificationRequirement.REQUIRED)
                .build();
        String token = storeChallenge(username, REMOVAL, null, options, now);
        return new StartedChallenge(token, options, now.plus(challengeTtl));
    }

    public void completeRemoval(
            String username,
            String challengeToken,
            String credentialId,
            PublicKeyCredential<AuthenticatorAssertionResponse> credential,
            Instant now) {
        PublicKeyCredentialRequestOptions options =
                consumeOptions(username, REMOVAL, challengeToken, null, PublicKeyCredentialRequestOptions.class, now);
        if (credential == null || credentialId == null || credentialId.isBlank()) {
            throw new BadCredentialsException("Authentication failed");
        }
        org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity verifiedUser;
        try {
            verifiedUser = relyingParty.authenticate(new RelyingPartyAuthenticationRequest(options, credential));
        } catch (VerificationException | IllegalArgumentException exception) {
            throw new BadCredentialsException("Authentication failed", exception);
        }
        var owner = users.findByUsername(username);
        CredentialRecord record = credentials.findByCredentialId(credential.getRawId());
        if (verifiedUser == null
                || owner == null
                || !username.equals(verifiedUser.getName())
                || record == null
                || !record.getUserEntityUserId().equals(owner.getId())
                || !credential.getRawId().toBase64UrlString().equals(credentialId)) {
            throw new BadCredentialsException("Authentication failed");
        }
        credentials.delete(record.getCredentialId());
    }

    private String storeChallenge(
            String username, String operation, String transactionHash, Object options, Instant now) {
        try {
            byte[] randomToken = new byte[32];
            random.nextBytes(randomToken);
            String token = Base64.getUrlEncoder().withoutPadding().encodeToString(randomToken);
            challenges.save(
                    hash(token),
                    new WebAuthnMfaChallenge(
                            username,
                            operation,
                            transactionHash,
                            mapper.writeValueAsBytes(options),
                            now.plus(challengeTtl)));
            return token;
        } catch (JacksonException exception) {
            throw new IllegalStateException("Could not create WebAuthn challenge", exception);
        }
    }

    private <T> T consumeOptions(
            String username, String operation, String token, String transactionHash, Class<T> type, Instant now) {
        if (token == null || token.isBlank()) throw new BadCredentialsException("Authentication failed");
        WebAuthnMfaChallenge challenge = challenges
                .consume(hash(token), username, operation, transactionHash, now)
                .orElseThrow(() -> new BadCredentialsException("Authentication failed"));
        try {
            return mapper.readValue(challenge.options(), type);
        } catch (JacksonException exception) {
            throw new BadCredentialsException("Authentication failed", exception);
        }
    }

    private static PublicKeyCredentialRequestOptions requireUserVerification(
            PublicKeyCredentialRequestOptions options) {
        return PublicKeyCredentialRequestOptions.builder()
                .challenge(options.getChallenge())
                .timeout(options.getTimeout())
                .rpId(options.getRpId())
                .allowCredentials(options.getAllowCredentials())
                .extensions(options.getExtensions())
                .userVerification(UserVerificationRequirement.REQUIRED)
                .build();
    }

    private static PublicKeyCredentialCreationOptions requireUserVerification(
            PublicKeyCredentialCreationOptions options) {
        var criteria = options.getAuthenticatorSelection();
        var selection = AuthenticatorSelectionCriteria.builder()
                .authenticatorAttachment(criteria.getAuthenticatorAttachment())
                .residentKey(criteria.getResidentKey())
                .userVerification(UserVerificationRequirement.REQUIRED)
                .build();
        return PublicKeyCredentialCreationOptions.builder()
                .rp(options.getRp())
                .user(options.getUser())
                .challenge(options.getChallenge())
                .pubKeyCredParams(options.getPubKeyCredParams())
                .timeout(options.getTimeout())
                .excludeCredentials(options.getExcludeCredentials())
                .authenticatorSelection(selection)
                .attestation(options.getAttestation())
                .extensions(options.getExtensions())
                .build();
    }

    private static Authentication authentication(String username) {
        return UsernamePasswordAuthenticationToken.authenticated(username, null, List.of());
    }

    private static String hash(String value) {
        try {
            return Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(
                            MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required", exception);
        }
    }

    public record StartedChallenge(String challengeToken, Object publicKey, Instant expiresAt) {}

    public record Credential(String id, String label) {}

    public record RegistrationProof(PublicKeyCredential<AuthenticatorAttestationResponse> credential, String label) {}

    public record LoginProof(
            @com.fasterxml.jackson.annotation.JsonProperty("challenge_token")
            String challengeToken,

            PublicKeyCredential<AuthenticatorAssertionResponse> credential) {}
}

package io.zhijun.security.autoconfigure;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.webauthn.api.AuthenticatorAssertionResponse;
import org.springframework.security.web.webauthn.api.PublicKeyCredential;
import org.springframework.security.web.webauthn.jackson.WebauthnJacksonModule;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;

/** Current-user MFA enrollment, status and removal endpoints. */
public final class MfaManagementFilter extends OncePerRequestFilter {

    private final String basePath;
    private final String webauthnOptionsPath;
    private final TotpMfaService totpMfaService;
    private final EmailMfaService emailMfaService;
    private final AuthSecurityProperties.Mfa properties;
    private final String issuer;
    private final JsonMapper jsonMapper;
    private final AuthenticationFailureHandler failureHandler;
    private final Clock clock;
    private final WebAuthnMfaService webAuthnMfaService;
    private final MfaLoginTransactionService loginTransactions;

    public MfaManagementFilter(
            String basePath,
            String webauthnOptionsPath,
            TotpMfaService totpMfaService,
            EmailMfaService emailMfaService,
            AuthSecurityProperties.Mfa properties,
            String issuer,
            JsonMapper jsonMapper,
            AuthenticationFailureHandler failureHandler,
            Clock clock,
            WebAuthnMfaService webAuthnMfaService,
            MfaLoginTransactionService loginTransactions) {
        this.basePath = stripTrailingSlash(basePath);
        this.webauthnOptionsPath = webauthnOptionsPath;
        this.totpMfaService = totpMfaService;
        this.emailMfaService = emailMfaService;
        this.properties = properties;
        this.issuer = issuer;
        this.jsonMapper =
                jsonMapper.rebuild().addModule(new WebauthnJacksonModule()).build();
        this.failureHandler = failureHandler;
        this.clock = clock;
        this.webAuthnMfaService = webAuthnMfaService;
        this.loginTransactions = loginTransactions;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String path = request.getServletPath();
        if (!isManagedPath(path)) {
            filterChain.doFilter(request, response);
            return;
        }
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
        try {
            if (webAuthnMfaService != null
                    && HttpMethod.POST.matches(request.getMethod())
                    && path.equals(webauthnOptionsPath)) {
                LoginOptionsRequest loginRequest = read(request, LoginOptionsRequest.class);
                if (loginRequest == null
                        || loginRequest.transactionToken() == null
                        || loginRequest.transactionToken().isBlank()
                        || loginTransactions == null) {
                    throw new BadCredentialsException("Authentication failed");
                }
                String username =
                        loginTransactions.usernameFor(loginRequest.transactionToken(), "webauthn", clock.instant());
                write(
                        response,
                        HttpServletResponse.SC_OK,
                        webAuthnMfaService.beginLogin(username, loginRequest.transactionToken(), clock.instant()));
                return;
            }
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String username = requireAuthenticated(authentication);
            if (HttpMethod.GET.matches(request.getMethod()) && path.equals(basePath)) {
                write(
                        response,
                        HttpServletResponse.SC_OK,
                        new Status(
                                totpMfaService != null && totpMfaService.isEnrolled(username),
                                emailMfaService != null && emailMfaService.isEnabled(username),
                                webAuthnMfaService != null && webAuthnMfaService.isEnrolled(username),
                                webAuthnMfaService == null
                                        ? java.util.List.of()
                                        : webAuthnMfaService.credentials(username)));
            } else if (totpMfaService != null
                    && HttpMethod.POST.matches(request.getMethod())
                    && path.equals(basePath + "/totp")) {
                TotpMfaService.Enrollment enrollment = totpMfaService.beginEnrollment(username, issuer);
                write(
                        response,
                        HttpServletResponse.SC_OK,
                        new TotpEnrollmentResponse(
                                enrollment.secret(), enrollment.otpauthUri(), enrollment.expiresAt()));
            } else if (totpMfaService != null
                    && HttpMethod.POST.matches(request.getMethod())
                    && path.equals(basePath + "/totp/verify")) {
                Proof proof = readProof(request);
                if (!totpMfaService.confirmEnrollment(username, proof.code())) {
                    throw new BadCredentialsException("Authentication failed");
                } else {
                    response.setStatus(HttpServletResponse.SC_NO_CONTENT);
                }
            } else if (totpMfaService != null
                    && HttpMethod.DELETE.matches(request.getMethod())
                    && path.equals(basePath + "/totp")) {
                Proof proof = readProof(request);
                if (!totpMfaService.verify(username, proof.code())) {
                    throw new BadCredentialsException("Authentication failed");
                }
                totpMfaService.remove(username);
                response.setStatus(HttpServletResponse.SC_NO_CONTENT);
            } else if (emailMfaService != null
                    && HttpMethod.POST.matches(request.getMethod())
                    && path.equals(basePath + "/email")) {
                EmailMfaService.Challenge challenge =
                        emailMfaService.beginEnrollment(username, properties.transactionTtl(), clock.instant());
                write(
                        response,
                        HttpServletResponse.SC_OK,
                        new EmailEnrollmentResponse(challenge.token(), challenge.expiresAt()));
            } else if (emailMfaService != null
                    && HttpMethod.POST.matches(request.getMethod())
                    && path.equals(basePath + "/email/verify")) {
                EmailEnrollmentProof proof = readEmailEnrollmentProof(request);
                if (!emailMfaService.confirmEnrollment(
                        username,
                        proof.challengeToken(),
                        proof.code(),
                        clock.instant(),
                        properties.maximumAttempts())) {
                    throw new BadCredentialsException("Authentication failed");
                }
                response.setStatus(HttpServletResponse.SC_NO_CONTENT);
            } else if (emailMfaService != null
                    && HttpMethod.DELETE.matches(request.getMethod())
                    && path.equals(basePath + "/email")) {
                if (!emailMfaService.isEnabled(username)) {
                    throw new BadCredentialsException("Authentication failed");
                }
                EmailMfaService.Challenge challenge =
                        emailMfaService.beginRemoval(username, properties.transactionTtl(), clock.instant());
                write(
                        response,
                        HttpServletResponse.SC_ACCEPTED,
                        new EmailEnrollmentResponse(challenge.token(), challenge.expiresAt()));
            } else if (emailMfaService != null
                    && HttpMethod.POST.matches(request.getMethod())
                    && path.equals(basePath + "/email/remove/verify")) {
                EmailEnrollmentProof proof = readEmailEnrollmentProof(request);
                if (!emailMfaService.confirmRemoval(
                        username,
                        proof.challengeToken(),
                        proof.code(),
                        clock.instant(),
                        properties.maximumAttempts())) {
                    throw new BadCredentialsException("Authentication failed");
                }
                response.setStatus(HttpServletResponse.SC_NO_CONTENT);
            } else if (webAuthnMfaService != null
                    && HttpMethod.POST.matches(request.getMethod())
                    && path.equals(basePath + "/webauthn/register/options")) {
                write(
                        response,
                        HttpServletResponse.SC_OK,
                        webAuthnMfaService.beginRegistration(username, clock.instant()));
            } else if (webAuthnMfaService != null
                    && HttpMethod.POST.matches(request.getMethod())
                    && path.equals(basePath + "/webauthn/register")) {
                RegistrationRequest proof = read(request, RegistrationRequest.class);
                if (proof == null || proof.publicKey() == null) {
                    throw new BadCredentialsException("Authentication failed");
                }
                webAuthnMfaService.completeRegistration(
                        username,
                        proof.challengeToken(),
                        new WebAuthnMfaService.RegistrationProof(
                                proof.publicKey().credential(),
                                proof.publicKey().label()),
                        clock.instant());
                response.setStatus(HttpServletResponse.SC_NO_CONTENT);
            } else if (webAuthnMfaService != null
                    && HttpMethod.POST.matches(request.getMethod())
                    && path.equals(basePath + "/webauthn/remove/options")) {
                CredentialRequest target = read(request, CredentialRequest.class);
                if (target == null
                        || target.credentialId() == null
                        || target.credentialId().isBlank()) {
                    throw new BadCredentialsException("Authentication failed");
                }
                write(
                        response,
                        HttpServletResponse.SC_OK,
                        webAuthnMfaService.beginRemoval(username, target.credentialId(), clock.instant()));
            } else if (webAuthnMfaService != null
                    && HttpMethod.POST.matches(request.getMethod())
                    && path.equals(basePath + "/webauthn/remove")) {
                RemovalRequest proof = read(request, RemovalRequest.class);
                if (proof == null) {
                    throw new BadCredentialsException("Authentication failed");
                }
                webAuthnMfaService.completeRemoval(
                        username, proof.challengeToken(), proof.credentialId(), proof.proof(), clock.instant());
                response.setStatus(HttpServletResponse.SC_NO_CONTENT);
            } else {
                response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            }
        } catch (AuthenticationException exception) {
            failureHandler.onAuthenticationFailure(request, response, exception);
        } catch (RuntimeException exception) {
            failureHandler.onAuthenticationFailure(
                    request,
                    response,
                    new AuthenticationServiceException("Authentication could not be completed", exception));
        }
    }

    private boolean isManagedPath(String path) {
        return path.equals(basePath)
                || (totpMfaService != null
                        && (path.equals(basePath + "/totp") || path.equals(basePath + "/totp/verify")))
                || (emailMfaService != null
                        && (path.equals(basePath + "/email")
                                || path.equals(basePath + "/email/verify")
                                || path.equals(basePath + "/email/remove/verify")))
                || (webAuthnMfaService != null
                        && (path.equals(webauthnOptionsPath) || path.startsWith(basePath + "/webauthn/")));
    }

    private String requireAuthenticated(Authentication authentication) {
        if (authentication == null
                || !authentication.isAuthenticated()
                || !(authentication.getPrincipal() instanceof Jwt)) {
            throw new BadCredentialsException("Authentication failed");
        }
        return authentication.getName();
    }

    private Proof readProof(HttpServletRequest request) {
        Proof proof = read(request, Proof.class);
        if (proof == null || proof.code() == null || !proof.code().matches("[0-9]{6}")) {
            throw new BadCredentialsException("Authentication failed");
        }
        return proof;
    }

    private EmailEnrollmentProof readEmailEnrollmentProof(HttpServletRequest request) {
        EmailEnrollmentProof proof = read(request, EmailEnrollmentProof.class);
        if (proof == null
                || proof.challengeToken() == null
                || proof.challengeToken().isBlank()
                || proof.code() == null
                || !proof.code().matches("[0-9]{6}")) {
            throw new BadCredentialsException("Authentication failed");
        }
        return proof;
    }

    private <T> T read(HttpServletRequest request, Class<T> type) {
        try {
            return jsonMapper.readValue(request.getInputStream(), type);
        } catch (IOException | JacksonException exception) {
            throw new BadCredentialsException("Authentication failed", exception);
        }
    }

    private void write(HttpServletResponse response, int status, Object body) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader("Cache-Control", "no-store");
        jsonMapper.writeValue(response.getOutputStream(), body);
    }

    private static String stripTrailingSlash(String path) {
        return path.endsWith("/") ? path.substring(0, path.length() - 1) : path;
    }

    public record Status(
            boolean totpEnrolled,
            boolean emailEnabled,
            boolean webauthnEnrolled,
            java.util.List<WebAuthnMfaService.Credential> webauthnCredentials) {}

    public record TotpEnrollmentResponse(
            String secret,
            @JsonProperty("otpauth_uri") String otpauthUri,
            @JsonProperty("expires_at") Instant expiresAt) {}

    public record EmailEnrollmentResponse(
            @JsonProperty("challenge_token") String challengeToken,
            @JsonProperty("expires_at") Instant expiresAt) {}

    public record EmailEnrollmentProof(
            @JsonProperty("challenge_token") String challengeToken, String code) {}

    public record Proof(String code) {}

    public record LoginOptionsRequest(
            @JsonProperty("transaction_token") String transactionToken) {}

    public record RegistrationRequest(
            @JsonProperty("challenge_token") String challengeToken, RegistrationPublicKey publicKey) {}

    public record RegistrationPublicKey(
            org.springframework.security.web.webauthn.api.PublicKeyCredential<
                            org.springframework.security.web.webauthn.api.AuthenticatorAttestationResponse>
                    credential,
            String label) {}

    public record RemovalRequest(
            @JsonProperty("challenge_token") String challengeToken,
            @JsonProperty("credential_id") String credentialId,
            PublicKeyCredential<AuthenticatorAssertionResponse> proof) {}

    public record CredentialRequest(
            @JsonProperty("credential_id") String credentialId) {}
}

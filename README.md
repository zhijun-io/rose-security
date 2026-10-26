# Rose Security

[![Java 25](https://img.shields.io/badge/Java-25-orange?logo=openjdk&logoColor=white)](https://openjdk.org/)
[![Spring Boot 4.1.2](https://img.shields.io/badge/Spring%20Boot-4.1.2-6DB33F?logo=springboot&logoColor=white)](https://spring.io/projects/spring-boot)
[![CI](https://github.com/zhijun-io/rose-security/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/zhijun-io/rose-security/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/zhijun-io/rose-security)](LICENSE)
[![Codecov](https://codecov.io/gh/zhijun-io/rose-security/branch/main/graph/badge.svg?flag=library)](https://codecov.io/gh/zhijun-io/rose-security)

Spring Security integration for password authentication, JWT access tokens, revocable sessions, optional refresh-token rotation, and optional TOTP, Email, and WebAuthn MFA. The host application owns its user model, `SecurityFilterChain`, authorization rules, persistence choices, and API error responses.

## Support and scope

- Java 25, Spring Boot 4.1.2, Spring Security 7.
- Implemented: login/logout, JWT, sessions, optional refresh, JDBC/Redis session stores, optional TOTP/Email/WebAuthn MFA.
- Not implemented: OAuth2/OIDC login, authorization server, recovery codes, wallet or mnemonic MFA.
- Out of scope: registration, password management, application roles, business audit, and rate limiting.

MFA is opt-in and disabled by default. A user without an enrolled permitted factor can sign in with a password. MFA completion is required before the starter issues the authenticated session and tokens.

## Modules

| Artifact | Purpose |
|---|---|
| `rose-security-bom` | Aligns Rose Security dependency versions |
| `rose-security-core` | Token, session, and extension contracts |
| `rose-security-spring-boot-autoconfigure` | Authentication filters and Boot configuration |
| `rose-security-spring-boot-mfa` | Optional MFA contracts, providers, and filters |
| `rose-security-spring-boot-jdbc` | JDBC session-store adapter |
| `rose-security-spring-boot-redis` | Redis session-store adapter |
| `rose-security-spring-boot-starter` | Convenience dependency for base authentication |
| `rose-security-sample` | Runnable API and frontend example; excluded from coverage |

## Install

This repository currently builds `0.1.0-SNAPSHOT`; it is not a Maven Central release. Install it locally:

```sh
mise install
mise exec -- ./mvnw install
```

Import the BOM and add the modules you use:

```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>io.zhijun</groupId>
            <artifactId>rose-security-bom</artifactId>
            <version>0.1.0-SNAPSHOT</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>

<dependencies>
    <dependency>
        <groupId>io.zhijun</groupId>
        <artifactId>rose-security-spring-boot-starter</artifactId>
    </dependency>
    <!-- Optional integrations: rose-security-spring-boot-mfa,
         rose-security-spring-boot-jdbc, rose-security-spring-boot-redis -->
</dependencies>
```

The host supplies its `UserDetailsService`, password authentication, JWT signing keys (or encoder/decoder beans), and a session store. JDBC/Redis adapters require the corresponding host infrastructure. The sample uses ephemeral stores and is for local demonstration only.

## Configure the security chain

The library does not create a `SecurityFilterChain`. Apply its configurer to the host chain, set endpoint authorization, and configure CSRF/CORS for the host's token transport:

```java
@Bean
SecurityFilterChain apiSecurity(HttpSecurity http, AuthSecurityConfigurer auth) throws Exception {
    return http.securityMatcher("/api/**", "/.well-known/jwks.json")
            .with(auth, Customizer.withDefaults())
            .authorizeHttpRequests(authorize -> authorize
                    .requestMatchers(HttpMethod.POST,
                            "/api/auth/login", "/api/auth/refresh",
                            "/api/auth/logout", "/api/auth/logout-all",
                            "/api/auth/mfa/verify").permitAll()
                    .requestMatchers("/.well-known/jwks.json").permitAll()
                    .anyRequest().authenticated())
            .oauth2ResourceServer(resource -> resource.jwt(Customizer.withDefaults()))
            .build();
}
```

When using the MFA module, also inject `MfaSecurityConfigurer` and apply `.with(mfa, Customizer.withDefaults())`. Permit the configured MFA verification and WebAuthn options routes. Keep CSRF protection when authenticating with cookies; this example assumes bearer tokens. See the sample's [security configuration](rose-security-sample/src/main/java/io/zhijun/security/sample/SampleSecurityConfiguration.java).

Example properties (see `AuthSecurityProperties` and `MfaProperties` for the complete current property set):

```yaml
auth:
  security:
    jwt:
      refresh-enabled: true
      access-ttl: 10m
      refresh-ttl: 14d
      refresh-absolute-ttl: 30d
      issuer: https://auth.example.test
      audience: example-api
      private-key-file: ${AUTH_JWT_PRIVATE_KEY_FILE}
      public-key-file: ${AUTH_JWT_PUBLIC_KEY_FILE}
    mfa:
      enabled: false
      methods: [] # totp, email, webauthn
      transaction-ttl: 5m
      maximum-attempts: 5
```

Never commit signing keys or credentials. PEM keys are loaded at startup; use host-provided JWT beans for key-management integrations. Logout revokes the server-side session and refresh capability; an already issued stateless access token can remain valid until expiry unless the host adds a request-time revocation check.

## MFA responsibilities

The host provides factor storage and external services: `TotpCredentialStore`, `EmailMfaStore`, `MfaEmailSender`, WebAuthn repositories/challenge storage, and `MfaLoginTransactionStore`. Configure exact WebAuthn RP ID and allowed origins. Use durable shared implementations for multi-instance deployments. See [MFA details](docs/mfa-implementation-plan.md).

## Build, tests, and coverage

```sh
mise exec -- ./mvnw test
mise exec -- ./mvnw verify
```

The `coverage` profile generates an aggregate line-coverage report for library modules and excludes the sample. Codecov enforces an 80% project target for the `library` flag; Maven only generates the report and does not enforce the percentage locally:

```sh
mise exec -- ./mvnw -Pcoverage -pl rose-security-coverage -am verify
```

GitHub Actions uploads the aggregate JaCoCo report to Codecov. The badge reads the `library` flag directly from Codecov. For uploads to protected branches, configure the GitHub Actions secret `CODECOV_TOKEN` unless Codecov allows tokenless uploads for public repositories. See the [aggregate report](rose-security-coverage/target/site/jacoco-aggregate/index.html) after running the command locally. Run the sample with `mise run run`; frontend commands are listed in `mise.toml`.

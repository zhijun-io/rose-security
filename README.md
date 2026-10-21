# Rose Security Spring Boot Starter

A Spring Boot starter for local email/password authentication, JWT access tokens, revocable user sessions, and optional opaque refresh-token rotation. It integrates with Spring Security and leaves the host application in control of its security chain, account model, persistence, and API error contract.

## Project status

| Area | Status |
|---|---|
| Local login, access token, session tracking, single/all-session logout | Implemented |
| Refresh token rotation | Implemented; enabled by default and independently configurable |
| JDBC / Redis session stores | Optional adapters; auto-configured from available adapter and infrastructure beans |
| MFA | Not implemented |
| OAuth2 / OIDC client login | Not implemented |
| Authorization server | Out of scope |

Target baseline: Java 25, Spring Boot 4.1.1, Spring Security 7, Maven. Check the build files before adopting a different version line.

## Implemented capabilities

- **Filter-based authentication endpoints:** configurable login, refresh, logout, and logout-all paths. The host explicitly applies `AuthSecurityConfigurer` to its own `SecurityFilterChain`; the Starter does not claim or replace the chain.
- **Local email/password login:** authenticates through Spring Security's `AuthenticationManager` and `UserDetailsService`, then issues the Starter's own access token. The host owns user lookup and password encoding.
- **JWT access tokens:** default RS256 signing and validation with issuer, audience, expiry, session ID, security version, authentication time, and authentication-method claims. Keys come from a host `JWKSource`, configured PEM files, or host-provided Spring Security encoder/decoder beans.
- **Public signing keys:** when a `JWKSource` is available, `GET /.well-known/jwks.json` publishes public signing keys only. It does not provide OAuth2 authorization-server endpoints or discovery metadata.
- **Optional refresh-token flow:** opaque, high-entropy refresh tokens are returned in the response body, stored by hash, rotated on use, and replay-detected. Reusing a consumed token revokes its session family; if rotation commits but its response is lost, the client must sign in again. Refresh can be disabled independently; login still creates a session and issues an access token.
- **Revocable user sessions:** creates a session for each successful token login; supports single-session logout, logout-all, active-session lookup through `UserSessionService`, and session revocation through the store. This module does not define a session-list HTTP API.
- **Optional session persistence:** host-owned `UserSessionStore`, or the JDBC and Redis adapters. Refresh rotation is atomic in both adapters. JDBC schema is supplied as a template and must be applied by the host's migration tool.
- **Optional concurrent-session limit:** unlimited by default; can reject a new login or revoke the oldest session. Built-in stores enforce the limit atomically. The JDBC adapter uses a coordination row when the limit is enabled; see its documented cross-user serialization tradeoff.
- **Client details and remote-login hook:** captures client IP and a bounded User-Agent description for session records. Remote-login detection/notification is disabled by default and delegates to a host-provided handler.
- **Spring Security extension points:** host implementations can replace authentication, JWT encoding/decoding, session storage, success/failure handling, logout behavior, and client-detail extraction through standard Spring Security interfaces or the documented Starter contracts.

MFA, OAuth2/OIDC client login, authorization-server behavior, password management, user/account persistence, audit storage/event publishing, and session-list HTTP endpoints are not implemented. The Starter also does not add rate-limiting behavior or dependencies.

## Modules

| Module | Responsibility |
|---|---|
| `rose-security-spring-boot-starter-bom` | Aligns published starter artifacts |
| `rose-security-spring-boot-core` | Session and token contracts used by host applications |
| `rose-security-spring-boot-jdbc` | Optional JDBC `UserSessionStore` adapter and schema template |
| `rose-security-spring-boot-redis` | Optional Redis `UserSessionStore` adapter using atomic Lua scripts |
| `rose-security-spring-boot-autoconfigure` | Properties, conditional beans, and filter integration |
| `rose-security-spring-boot-starter` | Convenient dependency on the auto-configuration and its runtime requirements |
| `rose-security-sample` | Runnable host-owned security chain and React demo |

MFA and OAuth2/OIDC integration artifacts are not implemented. JDBC and Redis adapters are separate optional dependencies and are not pulled in by the main starter. No limiter dependency, configuration, storage, or extension point is provided.

## Add the dependency

Import the BOM and add the starter without a version:

```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>io.zhijun</groupId>
            <artifactId>rose-security-spring-boot-starter-bom</artifactId>
            <version>0.1.0</version>
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
</dependencies>
```

## Configuration

The `auth.security` auto-configuration is enabled by default. JWT login, session creation, logout, and logout-all are enabled by default; refresh is independently controlled by `auth.security.jwt.refresh-enabled`. JWT issuance requires issuer and audience values plus a host-provided signing-key integration.

```yaml
auth:
  security:
    enabled: true
    jwt:
      refresh-enabled: true
      access-ttl: 10m
      refresh-ttl: 14d
      refresh-absolute-ttl: 30d
      issuer: https://auth.example.test
      audience: example-api
      active-key-id: current-signing-key # needed when the host JWKSource has multiple signing keys
    session-concurrency:
      maximum-active-sessions: 0 # 0 means unlimited
      when-limit-reached: deny-new # deny-new or revoke-oldest
    remote-login:
      enabled: false
    endpoints:
      base-path: /api/auth
      login: /login
      refresh: /refresh
      logout: /logout
      logout-all: /logout-all
```

For the default Nimbus encoder and decoder, use either a host `JWKSource<SecurityContext>` bean or configure external PEM files. A host `JWKSource` takes precedence when both are present:

```yaml
auth:
  security:
    jwt:
      private-key-file: ${AUTH_JWT_PRIVATE_KEY_FILE:/run/secrets/auth/jwt-private.pem}
      public-key-file: ${AUTH_JWT_PUBLIC_KEY_FILE:/run/secrets/auth/jwt-public.pem}
```

The private file must contain an unencrypted PKCS#8 RSA private key (`BEGIN PRIVATE KEY`); the public file must contain an X.509 RSA public key (`BEGIN PUBLIC KEY`). Both absolute paths are required, and the key pair must match and be at least 2048 bits. The files are loaded at startup and are not reloaded. PEM configuration provides one key pair and does not implement key rotation. A host can provide a multi-key `JWKSource` for verification-key publication; this alone does not rotate the signing key. To implement runtime signing-key selection, provide a custom `JwtTokenIssuer` and, when needed, a custom `JwtEncoder`/`JwtDecoder`. PEM keys receive a stable fingerprint-based `kid`. When a host JWKSource contains multiple signing keys, set `auth.security.jwt.active-key-id` to the active key's matching `kid`; the default issuer uses that configured key ID. Keep the private key in a secret mount with restrictive permissions. Alternatively, provide both Spring Security `JwtEncoder` and `JwtDecoder` beans and omit JWK source/key-file configuration; in that case JWKS publication is unavailable unless a `JWKSource` is also provided.

| Property | Default | Notes |
|---|---|---|
| `auth.security.enabled` | `true` | Disables all Starter auto-configuration when false |
| `auth.security.jwt.refresh-enabled` | `true` | When false, removes the refresh filter and omits refresh fields from login responses; sessions still exist and expire with the access token |
| `auth.security.jwt.access-ttl` | `10m` | Must be positive |
| `auth.security.jwt.refresh-ttl` | `14d` | Must be positive and no greater than the absolute lifetime when refresh is enabled |
| `auth.security.jwt.refresh-absolute-ttl` | `30d` | Maximum lifetime of one session family |
| `auth.security.jwt.issuer` | empty | Required when token support is enabled |
| `auth.security.jwt.audience` | empty | Required when token support is enabled |
| `auth.security.jwt.active-key-id` | inferred when a single JWKSource signing key has a `kid`; otherwise omitted | Selects the signing key in a multi-key host JWKSource and writes its `kid` into JWT headers |
| `auth.security.jwt.private-key-file` | unset | Optional absolute path to an unencrypted PKCS#8 RSA private key PEM; configure with `public-key-file` together |
| `auth.security.jwt.public-key-file` | unset | Optional absolute path to an X.509 RSA public key PEM; configure with `private-key-file` together |
| `auth.security.session-concurrency.maximum-active-sessions` | `0` | Maximum active sessions per username; `0` means unlimited |
| `auth.security.session-concurrency.when-limit-reached` | `deny-new` | `deny-new` or `revoke-oldest`; oldest is ordered by session creation time |
| `auth.security.remote-login.enabled` | `false` | Enables the host-provided `RemoteLoginHandler` after a successful login token response |
| `auth.security.endpoints.base-path` | `/api/auth` | Prefix combined with each endpoint path |
| `auth.security.endpoints.login` | `/login` | `POST`, JSON email/password |
| `auth.security.endpoints.refresh` | `/refresh` | `POST`, JSON refresh token; filter exists only when refresh is enabled |
| `auth.security.endpoints.logout` | `/logout` | `POST`, Bearer Access Token |
| `auth.security.endpoints.logout-all` | `/logout-all` | `POST`, Bearer Access Token |

When token issuance is enabled with a `JWKSource`, the Starter exposes public signing keys at `GET /.well-known/jwks.json`. It strips private key material and requires unique `kid` values when multiple RSA signing keys are published. The host owns its `SecurityFilterChain` and must permit this path anonymously. The endpoint does not add OAuth2 authorization-server behavior or discovery metadata.

Endpoint paths are validated for absolute form and collisions. The host remains responsible for checking conflicts with application routes. Setting `auth.security.enabled=false` disables all Starter auto-configuration; disabling refresh leaves the configured refresh path unhandled by this Starter.

`AuthSecurityAutoConfiguration` registers the properties when `auth.security.enabled=true` (the default); JWT login and session support are part of this core behavior. Set `auth.security.enabled=false` to disable the Starter as a whole. Use one of these key integrations: provide `JWKSource<SecurityContext>`; configure both RSA PEM file properties so the Starter creates a JWK source; or provide Spring Security `JwtEncoder` and `JwtDecoder` beans directly. A host `JWKSource` takes precedence over file properties. The PEM option accepts an unencrypted PKCS#8 RSA private key and an X.509 RSA public key, requires matching keys of at least 2048 bits, and reads them from absolute filesystem paths. Keep the private key outside the repository and restrict file permissions. Token session services need `UserDetailsService` and `UserSecurityVersionProvider`. Select a JDBC or Redis store below, or provide a host `UserSessionStore`. Filter integration is conditional on the Starter being enabled plus `UserSessionService` and `JwtDecoder`; even when present, the configurer only adds filters after the host explicitly applies it to its own chain. Missing required beans while the Starter is enabled result in startup failure rather than a production in-memory fallback.

### Optional JDBC and Redis stores

Add the adapter and its normal Spring Boot infrastructure starter. `@ConditionalOnMissingBean(UserSessionStore.class)` preserves a host implementation if one is present.

```xml
<!-- JDBC: also add spring-boot-starter-jdbc and the database driver -->
<dependency>
    <groupId>io.zhijun</groupId>
    <artifactId>rose-security-spring-boot-jdbc</artifactId>
</dependency>

<!-- Or Redis: also add spring-boot-starter-data-redis -->
<dependency>
    <groupId>io.zhijun</groupId>
    <artifactId>rose-security-spring-boot-redis</artifactId>
</dependency>
```

Session storage is selected from available host infrastructure: the JDBC adapter backs off unless `JdbcTemplate` and a transaction manager are present; Redis backs off unless `StringRedisTemplate` is present. If both adapters are available, JDBC takes precedence. A host-provided `UserSessionStore` always replaces both defaults. If neither adapter is available, the host must provide `UserSessionStore`; startup fails rather than using in-memory storage. Add only the adapter and infrastructure you intend to use. The JDBC schema template is at `db/rose-security-session-store-schema.sql` in the JDBC artifact; it is not run automatically. Apply it through the host's migration tool. When a positive session concurrency limit is enabled, the adapter locks the single `user_session_creation_lock` coordination row while evaluating and creating sessions; this guarantees correctness even for a user's first concurrent logins, at the cost of serializing limited session creation across users. Keep database timestamps in UTC. Purge expired session families through the host's normal maintenance process, deleting rows from `user_session_refresh_tokens` before `user_sessions`, for example:

```sql
DELETE FROM user_session_refresh_tokens
WHERE session_id IN (
    SELECT session_id FROM user_sessions WHERE absolute_expires_at <= CURRENT_TIMESTAMP
);
DELETE FROM user_sessions WHERE absolute_expires_at <= CURRENT_TIMESTAMP;
```

The Redis adapter uses `StringRedisTemplate` and Lua scripts for atomic create, concurrency-limit enforcement, refresh rotation, replay revocation, single-session revocation, and all-session revocation. All keys use one Redis Cluster hash tag so the scripts remain atomic on a cluster; this concentrates the adapter's keys in one slot and can limit cluster write scaling. Session hashes expire at their absolute expiry; consumed refresh-token markers remain until that same time so replay can still be detected. Select the adapter only after checking this storage and scaling tradeoff for the deployment.

## Host responsibilities and security-chain integration

The Starter does not create or replace a `SecurityFilterChain`. The host must provide a chain, a `UserDetailsService`, and `UserSecurityVersionProvider`; provide `UserSessionStore` or add a session-store adapter and its infrastructure dependency for automatic selection. For the default password flow, also provide a `PasswordEncoder`; Spring Security builds the `AuthenticationManager` from the configured authentication providers. A host with a custom authentication flow can provide its own `AuthenticationManager` or `AuthenticationProvider`. When an `AuthenticationManager` bean is present, the Starter uses the unique or `@Primary` bean; otherwise it uses Spring Security's `AuthenticationConfiguration`. The default JWT path needs a `JWKSource<SecurityContext>` bean or both configured PEM file paths. Alternatively, provide compatible Spring Security `JwtEncoder` and `JwtDecoder` beans. The default issuer signs RS256 tokens. A host using another signing algorithm must provide a compatible `JwtTokenIssuer`, encoder, and decoder. If using a custom `UserSessionStore` and a positive session limit, override its atomic `create(session, refreshTokenHash, policy)` method; the default method fails closed rather than silently applying a racy limit.

The configurer adds Spring Security `AuthenticationFilter` instances for login and (when enabled) refresh, and configures the chain's existing logout filter. The host chooses authorization rules, CORS, CSRF, exception handling, and resource-server configuration. For a Bearer-header-only API that does not authenticate with cookies, a host can scope a stateless chain to its API paths and choose an explicit CSRF policy. Keep CSRF protection for cookie-authenticated requests.

```java
@Bean
SecurityFilterChain apiSecurity(HttpSecurity http, AuthSecurityConfigurer auth) throws Exception {
    return http.securityMatcher("/api/**")
            .with(auth, Customizer.withDefaults())
            .authorizeHttpRequests(authorize -> authorize
                    .requestMatchers(HttpMethod.POST,
                            "/api/auth/login", "/api/auth/refresh",
                            "/api/auth/logout", "/api/auth/logout-all").permitAll()
                    .anyRequest().authenticated())
            .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()))
            .csrf(AbstractHttpConfigurer::disable)
            .build();
}
```

This chain example assumes the API does not use cookies. The sample has a complete configuration, including a separate deny-all chain for routes it does not own: [SampleSecurityConfiguration](rose-security-sample/src/main/java/io/zhijun/security/sample/SampleSecurityConfiguration.java).

## Authentication and session behavior

- Login accepts `POST /api/auth/login` with `{"email":"person@example.test","password":"…"}` and authenticates through the host's Spring Security `AuthenticationManager`.
- Access tokens are signed JWTs with issuer, audience, timestamps, `sid`, `security_version`, `auth_time`, and `amr` claims. Use Spring Security's Resource Server support to validate Bearer tokens.
- Refresh tokens are 256-bit opaque random values. Only their SHA-256 hashes are passed to `UserSessionStore`. Rotation must atomically consume the old hash and install the replacement. Reuse of a consumed token revokes its whole session family; clients should single-flight refresh calls so ordinary concurrent API requests do not trigger replay handling.
- When refresh is disabled, login still records a `UserSession`; no refresh token is issued and its session lifetime equals the access-token lifetime.
- Logout revokes the current session; logout-all revokes all sessions for the authenticated username. Both require a valid Bearer Access Token.
- `UserSessionService` can query active sessions for a username. The Starter does not expose a fixed HTTP session-list API; the host decides whether and how to expose that operation.
- New-session admission uses `UserSessionConcurrencyPolicy`. The default limit is unlimited; a positive limit applies atomically at the store boundary. `revoke-oldest` removes the oldest session's refresh capability, but its already-issued Access Token may remain accepted until expiry.
- Access JWT validation is stateless by default. Revoking a session prevents later refresh but does not invalidate an already-issued Access Token before expiry. Immediate access-token revocation requires a host-side request-time check of session state or security version.
- `UserSecurityVersionProvider` lets the host invalidate refresh sessions after password changes, account disablement, or other security changes. The host should also revoke sessions when policy requires immediate logout.
- Session storage must be shared by application instances and implement refresh rotation atomically. Optional JDBC and Redis adapters are provided; the sample's in-memory store is for demonstration only.

Token responses contain `access_token`, `token_type`, `expires_in`, and `session_id`; refresh mode also returns `refresh_token` and `refresh_expires_at`. Responses set `Cache-Control: no-store` and `Pragma: no-cache`. The Starter returns tokens in the response body; clients should protect them from XSS, avoid persistent browser storage where possible, and clear them on logout. Refresh-token response-body transport does not require cookie CSRF handling, but the host still owns its chain's CSRF and CORS policy.

The default decoder validates RS256, issuer, audience, and standard JWT timestamps. The default issuer writes its configured signing key's `kid` into the JWT header. The JWKS endpoint publishes matching public RSA signing keys only; when publishing multiple keys, each must have a unique `kid`. The Starter does not generate, activate, schedule, or rotate signing keys. A host that implements rotation can provide its own `JWKSource` and `JwtTokenIssuer` (and replace `JwtEncoder`/`JwtDecoder` if its key integration requires it), publish the new public key before signing with it, and retain old verification keys until old tokens expire. The host also owns key-cache propagation and the response to key compromise.

## Spring Security extension points

Host beans replace defaults using Spring Security interfaces. Define the corresponding bean before auto-configuration backs off:

| Behavior | Extension point |
|---|---|
| Password authentication | `UserDetailsService`; for the default password flow, a host `PasswordEncoder`; optionally customize with `AuthenticationManager` / `AuthenticationProvider` |
| JWT encoding and decoding | `JwtEncoder` and `JwtDecoder` |
| JWT claim/signing behavior | `JwtTokenIssuer` |
| Session persistence and semantics | `UserSessionStore` or `UserSessionService` |
| Per-user concurrency limits | `UserSessionConcurrencyPolicy`; custom `UserSessionStore` implementations must enforce limits atomically |
| Login success | `AuthenticationSuccessHandler` bean `authSecurityLoginSuccessHandler` (default: `TokenAuthenticationSuccessHandler`) |
| Refresh success | `AuthenticationSuccessHandler` bean `authSecurityRefreshSuccessHandler` (default: `RefreshTokenAuthenticationSuccessHandler`) |
| Login / refresh failure | `AuthenticationFailureHandler`; default bean name `authSecurityAuthenticationFailureHandler` |
| Logout revocation | `LogoutHandler` bean named `authSecurityLogoutHandler` (default: `UserSessionLogoutHandler`) |
| Logout response | `LogoutSuccessHandler` bean named `authSecurityLogoutSuccessHandler` (default: `UserSessionLogoutSuccessHandler`) |
| Client IP and device details | `AuthenticationDetailsSource<HttpServletRequest, UserSessionClientInfo>` |
| Remote-login detection and notification | `RemoteLoginHandler` when `auth.security.remote-login.enabled=true` |

`DefaultUserSessionClientInfoDetailsSource` is non-final and can be subclassed to override `resolveClientIp` or `describeDevice`. It reads only `HttpServletRequest.getRemoteAddr()` by default and ignores forwarding headers. Trust forwarded client addresses only when the application has configured and verified its trusted proxy boundary. User-Agent parsing is capped at 512 characters; the raw value is not stored.

The default login success handler expects the configured `AuthenticationManager` to return a Spring Security `UserDetails` principal and labels the method as `pwd`, matching the built-in email/password converter. If a host manager authenticates a different principal type or authentication method, replace `authSecurityLoginSuccessHandler` with an `AuthenticationSuccessHandler` that issues tokens with the correct claims (or compose its own filter flow).

Remote-login detection is disabled by default. When enabled, the default login success handler requires a host `RemoteLoginHandler` bean and calls it after writing the token response, passing only the username, `UserSessionClientInfo` (IP/device), and session ID. The host owns the definition of “remote” (for example, GeoIP lookup and comparison with its login history) and notification delivery; the Starter adds no GeoIP database, email dependency, storage, or event system. A custom login success handler must invoke this extension itself if the feature remains enabled. Handler failures are logged without request details and do not invalidate an already-issued login response; implementations should enqueue external notifications and avoid blocking the login thread.

`AuthSecurityConfigurer` is a final `AbstractHttpConfigurer`; apply it to the host's chain rather than subclassing it. If its endpoint protocol does not fit, compose Spring Security's native filters and handlers in the host chain. The default `AuthenticationFailureHandler` is Spring Security's `AuthenticationEntryPointFailureHandler` adapted to a 401 `HttpStatusEntryPoint`; it retains Spring Security's default behavior of rethrowing `AuthenticationServiceException`. Provide your own `AuthenticationFailureHandler` bean to choose the host's response behavior. Other API failures use the host's `AuthenticationEntryPoint` and `AccessDeniedHandler`. The Starter does not impose `ProblemDetail`, publish its own events, or define an API error schema.

The Starter does not implement audit storage or audit event publishing. Creating a `UserSession` is part of issuing tokens and has no separate audit callback. Spring Security authentication events can be used for the `AuthenticationManager` outcome, but they do not prove that token/session creation subsequently succeeded. The login and refresh filters have separate success handlers, so a host can audit the completed login token response and refresh response independently. A handler can establish that the response was serialized and flushed by the server; it cannot prove the client received it over the network. The two default logout roles are separate beans: replace the `LogoutHandler` to control or audit the actual revocation result, and replace the `LogoutSuccessHandler` to control the HTTP response. Spring Security's `LogoutSuccessEvent` describes the logout filter flow; it must not be treated as proof that this Starter's session revocation succeeded. The host owns audit persistence, event semantics, retention, and privacy rules.

## Sample and development

The runnable sample uses `demo@example.test` / `password`, an in-memory session store, and a newly generated RSA key on startup. These are local demonstration fixtures only. A restart invalidates sample sessions. Do not expose the sample as a production authentication service.

The sample frontend and backend run separately:

```bash
mise exec -- ./mvnw install
mise run frontend-install
mise run run
# in another terminal
mise run frontend-dev
```

Open <http://localhost:5173>. Vite proxies `/api/**` to the backend on port 8080. For the backend only, run `mise run run`. To package the frontend into the sample jar, run `mise run frontend-build`.

Run project checks with the pinned Java 25 toolchain:

```bash
mise exec -- ./mvnw test
mise exec -- ./mvnw verify
```

See [the design document](docs/rose-security-starter-design.md) for overall planned capabilities and [the MFA implementation plan](docs/mfa-implementation-plan.md) for the detailed MFA flow and unresolved decisions. See [the starter development prompt](docs/spring-security-starter-development-prompt.md) for project constraints and implementation conventions.

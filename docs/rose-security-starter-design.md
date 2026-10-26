# Rose Security architecture

This document describes the implementation in this repository. Build coordinates and code are the source of truth when details change.

## Runtime boundaries

| Module | Responsibility |
|---|---|
| `rose-security-core` | Token/session contracts and value types |
| `rose-security-spring-boot-autoconfigure` | JWT, authentication filters, session service, Boot configuration |
| `rose-security-spring-boot-mfa` | Optional MFA providers, stores, services, and filter integration |
| `rose-security-spring-boot-jdbc` | JDBC `UserSessionStore` |
| `rose-security-spring-boot-redis` | Redis `UserSessionStore` |
| `rose-security-spring-boot-starter` | Base authentication dependencies |
| `rose-security-bom` | Consumer dependency version alignment |
| `rose-security-sample` | Demonstration application; not a library module |

The host supplies its user lookup, password authentication, signing keys or JWT beans, and durable session/MFA stores. The library does not create a security chain; the host owns authorization, CSRF, CORS, proxy trust, and API error responses. Optional adapters activate only when their dependencies and infrastructure are present. The sample's in-memory stores are not suitable for production.

## Authentication lifecycle

Password login authenticates through Spring Security and creates a server-side session. Access tokens are JWTs. Refresh tokens, when enabled, are opaque random values whose hashes are stored and rotated; replay detection revokes the token family. Disabling refresh still allows sessions and logout. Stateless access tokens remain usable until expiry after logout unless the host adds request-time revocation checks.

MFA is an optional module and defaults to disabled. For users with enabled factors, password authentication creates a short-lived pending transaction. A successful factor verification completes authentication and only then creates the session/tokens. The host provides factor credential storage, email delivery, WebAuthn repositories, and pending-transaction storage.

## Extension approach

Prefer Spring Security's native interfaces when changing behavior: `AuthenticationManager`, `AuthenticationProvider`, `AuthenticationConverter`, success/failure handlers, logout handlers, `JwtEncoder`, and `JwtDecoder`. The configurers compose filters and remain applied to a host-owned `SecurityFilterChain`. Store interfaces define persistence and atomicity boundaries; implementations belong to the host or optional adapters.

OAuth2/OIDC login, authorization-server behavior, recovery codes, wallet/mnemonic factors, and business user/role management are not implemented by this repository.

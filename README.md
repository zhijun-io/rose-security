# Auth Security Spring Boot Starter

Reusable authentication and session infrastructure for Spring Boot API applications. This repository currently targets Java 25, Spring Boot 4.1.1, Spring Security 7, and Maven.

The project is being implemented in reviewable stages. The initial code slice provides the Maven multi-module layout, BOM, core extension contracts, validated static properties, conditional auto-configuration, a host-owned security-chain sample, and a React demo UI. JWT issuance/validation, refresh-token rotation, storage adapters, MFA providers, OAuth2/OIDC client login, authentication filters, and their persistence schemas are not implemented yet. Login, logout, and refresh will be implemented in the Spring Security filter chain rather than MVC controllers.

## Modules

| Module | Purpose |
|---|---|
| `auth-security-spring-boot-starter-bom` | Align versions for Starter artifacts |
| `auth-security-core` | Application-facing identity and signing-key contracts |
| `auth-security-spring-boot-autoconfigure` | Validated configuration and conditional Boot auto-configuration |
| `auth-security-spring-boot-starter` | Dependency-ready MVC/Spring Security starter |
| `auth-security-sample` | Minimal host application showing explicit chain ownership |

Optional modules are reserved in the BOM for OAuth2/OIDC, MFA factors, and JDBC/Redis storage and will be introduced with their implementations. They are not available dependencies yet.

## Use the starter (after publishing or local install)

Import the BOM and add the dependency without a version:

```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>dev.authstarter</groupId>
            <artifactId>auth-security-spring-boot-starter-bom</artifactId>
            <version>0.1.0</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>

<dependencies>
    <dependency>
        <groupId>dev.authstarter</groupId>
        <artifactId>auth-security-spring-boot-starter</artifactId>
    </dependency>
</dependencies>
```

The current snapshot can be installed with `mise exec -- ./mvnw install`. The application must provide its own `SecurityFilterChain`; the Starter deliberately does not claim all requests. Example configuration is in `auth-security-sample`, including a final deny-all chain so no routes fall outside the host's security policy.

## Current static properties

```yaml
auth:
  security:
    enabled: true
    token:
      enabled: false
      access-ttl: 10m
      refresh-ttl: 14d
      refresh-absolute-ttl: 30d
      issuer: ${AUTH_TOKEN_ISSUER:}
      audience: ${AUTH_TOKEN_AUDIENCE:}
      signing-algorithm: RS256
      key-provider: ${AUTH_SIGNING_KEY_PROVIDER:}
    endpoints:
      base-path: /api/auth
      login: /login
      refresh: /refresh
      logout: /logout
      logout-all: /logout-all
```

Token issuance remains disabled until a signing implementation is delivered. Enabling it now requires a non-empty issuer, audience, `RS256`, and key-provider identifier. MFA policies/factors and OAuth client registrations come from database-backed providers, not from these static properties.

## Build and run

The repository pins Java 25 in `mise.toml`; use the project toolchain because the system Java may differ:

```bash
mise exec -- ./mvnw test
mise exec -- ./mvnw verify
mise exec -- ./mvnw install -DskipTests
mise exec -- ./mvnw -f auth-security-sample/pom.xml spring-boot:run
```

The React 19 / Vite 8 sample lives in `auth-security-sample/frontend`. Maven `verify` installs the pinned Node/npm toolchain, runs frontend lint and unit checks, and builds the SPA into the sample jar. For hot reload, install the current snapshot once, then run the backend and frontend in separate terminals:

```bash
mise exec -- ./mvnw install
mise run frontend-install
mise run run
mise run frontend-dev
```

Open `http://localhost:5173`. Vite proxies `/api/**` to the sample backend on port 8080, so local development stays same-origin and requires no CORS setup. `mise run frontend-build` writes static assets into the sample module. The UI checks the health endpoint and shows the implementation roadmap; it does not pretend that the not-yet-implemented login/MFA/OIDC flows are available.

See [the design document](docs/auth-security-starter-design.md) for the architecture, security flows, pending decisions, and staged implementation plan. The `groupId` `dev.authstarter` remains provisional until publication coordinates are selected.

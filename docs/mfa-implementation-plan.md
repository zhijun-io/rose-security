# Optional MFA module

The `rose-security-spring-boot-mfa` module implements second-factor login for TOTP, Email, and WebAuthn. It is not pulled in by the base starter. MFA defaults to disabled; enabling factors requires both configuration and the host implementations listed below.

## Login flow

1. The host's password authentication succeeds.
2. If the user's policy requires an enrolled factor, the starter creates a short-lived pending login transaction and returns the available factor choices. It does not create an authenticated session or issue access/refresh tokens yet.
3. The client submits a factor proof and pending transaction token to the MFA verification filter.
4. The provider verifies the proof and current user state. On success, the normal login completion path creates the session and issues tokens.

Users with no enrolled allowed factor can complete password login. Removing the last factor returns the user to password-only login. MFA policy can come from configuration or a host `MfaPolicyProvider`.

## Host integrations

| Capability | Host implementation |
|---|---|
| Pending login state | `MfaLoginTransactionStore` with expiry and one-time completion |
| TOTP | `TotpCredentialStore`; protect secrets at rest and prevent replay |
| Email | `EmailMfaStore` and `MfaEmailSender` |
| WebAuthn | Spring Security WebAuthn credential repositories and `WebAuthnMfaChallengeStore` |

In a multi-instance deployment, use durable shared stores with atomic consume/complete operations. Set WebAuthn RP ID and an exact allowed-origin list. Never log or return factor secrets or proofs. Email transport, persistence, enrollment authorization, and rate limiting remain host responsibilities; this starter does not implement general request rate limiting.

## HTTP integration

Apply `MfaSecurityConfigurer` to the host's `SecurityFilterChain` when the MFA dependency is present. Permit the configured verification route and, when used, WebAuthn options route. The management filter exposes current-user MFA status and factor enrollment/removal operations; secure these routes through the host's chain. Default routes and configuration are defined in `MfaProperties` and summarized in the root README.

The sample uses in-memory factor and challenge stores for demonstration. They lose state on restart and must not be used for production.

## Not implemented

OAuth2/OIDC login, recovery codes, passkeys as primary login, wallet authentication, mnemonic credentials, and account recovery are not part of this MFA module.

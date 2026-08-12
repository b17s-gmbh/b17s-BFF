# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0-rc.2] - 2026-08-13
### Breaking Change
- Typed endpoints now sit on a three-rung auth ladder, making `AllowAnonymous()` and `AllowAnonymousWithOptionalAuth()` genuinely distinct (they were behavioral aliases):
  - `AllowAnonymous()` (and the require-nothing default) is now **credential-blind** on typed transformer endpoints: the auth context is never resolved, so the transformer always sees an empty `AuthContext`. Endpoints that personalized on optionally-present credentials under `AllowAnonymous()` must switch to `AllowAnonymousWithOptionalAuth()` — including the in-pipeline `IAuthenticationProvider` pattern (custom API keys, `AddReferenceTokenAuthentication`) where the endpoint skips the ASP.NET identity gate and a transformer gates on the provider-resolved `AuthContext`; see [authentication docs](docs/authentication.md#two-auth-layers-the-identity-gate-vs-the-provider).
  - `AllowAnonymousWithOptionalAuth()` resolves credentials when present (unchanged) and is now the only endpoint mode that may pair with optional backend auth (below).
  - Raw-forward endpoints sit on the same ladder: `AllowAnonymous()` raw-forwards are credential-blind too, `AllowAnonymousWithOptionalAuth()` (now available on `MapRawForward`, including the policy-gate overload) resolves optionally and supports `WithBackendAuth(policy, optional: true)`.
### Added
- Optional backend authentication, declared on the backend-auth call itself: `WithBackendAuth(policy, optional: true)`, `WithTokenExchange(audience, optional: true)`, and `WithUserToken(optional: true)` / `WithAuth(policy, optional: true)` on named backend legs. On an `AllowAnonymousWithOptionalAuth()` endpoint, the BFF converts a present frontend credential (cookie, bearer, custom provider) into the configured backend auth for authenticated callers and calls the backend with no auth for anonymous ones. The startup validator rejects every invalid placement: `optional: true` on `RequireAuth()` (dead config), on `AllowAnonymous()`/raw-forward (no optional resolution), on non-identity policies (nothing to apply), and *mandatory* user-identity backend auth on optional-auth endpoints (promises an identity anonymous callers lack). Trusted-host validation applies unchanged; `varyByUser` caching is rejected at startup on optional-auth endpoints (anonymous callers have no cache subject).
- `AllowAnonymousWithOptionalAuth(policy)`: optional authorization-policy gate for the authenticated treatment. Credentialed callers failing the policy are served the anonymous view (empty `AuthContext`, optional backend auth skipped) instead of a 403.
- `BackendAuthPolicies.ApiKey`: built-in backend-auth policy sending a fixed API key from configuration. Defaults to `Authorization: Bearer <token>`; `BackendService:ApiKey:Scheme` changes the scheme, `HeaderName` switches to a raw custom header (e.g. `X-Api-Key`). Per-backend keys via `BackendService:ApiKeys[backendName]` with the same fail-closed fallback rule as BasicAuth (`AllowGlobalApiKeyFallback`). Non-identity policy: valid on every endpoint auth mode, no trusted-host requirement.
- `BackendAuthPolicies.ClientCredentials`: built-in backend-auth policy authenticating with the BFF's **own** OAuth machine-to-machine identity via the client-credentials grant (RFC 6749 §4.4). Configured under `BackendService:ClientCredentials` (`TokenEndpoint`/`ClientId`/`ClientSecret` required, optional `Scope`/`Audience`) — deliberately separate from `SessionAuthentication`, nothing is inherited from the login client. Minted tokens are cached process-wide (`IClientCredentialsTokenService`) until 60s before expiry with single-flight acquisition; failures are never cached. Per-backend clients via `BackendService:ClientCredentialsBackends[backendName]`; a named backend without an entry fails as a 5xx-class configuration error unless `AllowGlobalClientCredentialsFallback` is set. Non-identity policy: valid on every endpoint auth mode, no trusted-host requirement. On a backend `401` the cached token is discarded and the call retried once with a freshly minted token (same `PortaCore:RefreshBackendTokenOn401` opt-out as the user-token refresh).
- `BackendAuthContext.ForceFreshCredential`: set on the 401-retry attempt so custom handlers that cache self-minted credentials can bypass/invalidate their cache; built-in handlers with static credentials ignore it.
- Claims refresh on token refresh (`PortaCore:RefreshClaimsFromIdToken`, default on): a successful refresh that returns a new `id_token` now updates the session cookie's claims from it, so IdP-side changes (roles granted/revoked) propagate without a re-login. Per re-asserted claim type the values are replaced (multi-value types as a set); types the new id_token omits stay untouched; protocol/login-time claims are never copied; the new token's `iss`/`sub` must match the session (OIDC Core §12.2) or the update is skipped with a warning while the tokens still rotate. See [authentication docs](docs/authentication.md#claims-refresh-on-token-refresh).

## [0.5.0-rc.1] - 2026-08-11
### Breaking Change
- The default OIDC challenge now uses automatic dispatch: safe top-level document navigations redirect to the identity provider, while fetches, unsafe methods, and embedded navigations receive a cache-disabled 401 problem response. Set `SessionAuthentication.Challenge.Mode` to `Interactive` to restore the previous always-redirect behavior.
- The default forbid scheme now returns a plain 403 instead of forwarding to the OIDC handler. Apps that configured `AccessDeniedPath` on the OIDC options no longer get that redirect from the default `ForbidAsync`; challenge (or forbid) the OIDC scheme explicitly to keep it.
### Added
- `SessionAuthentication.Challenge` configuration (`Mode`, `LoginPath`, and a code-only `Classifier` hook) controlling the new challenge dispatcher; see [oidc docs](docs/oidc.md#spas-and-expired-sessions).
- `bff.auth.challenges` counter (tag `outcome` = `redirect` | `unauthorized`) recording default-challenge dispatch decisions.

## [0.4.0] - 2026-07-06
### Changed
- Docs improvements
### Added
- `AllowForwardingHeaders(headers, destinationHosts?)` on `MapTransformer`/`MapPassThrough` endpoints: opts specific client request headers (e.g. `Accept-Language`, `X-Request-Id`) into the backend call without writing a custom transformer.
- `AddPortaHealthChecks()`: opt-in, zero-config health checks for Porta dependencies; see [health-checks docs](docs/health-checks.md).

## [0.3.1-rc.6] - 2026-06-23
### Added
- Warning during bootstrap and docs regarding backend catch-all route interpolation

## [0.3.0-rc.5] - 2026-06-18
### Added
- Per backend call caching
- Caching documentation

## [0.2.1-rc.4] - 2026-06-16
### Fixed
- `AddPortaReferenceTokenScheme` / `AddReferenceTokenAuthentication` now register `IDiscoveryService`, which `ReferenceTokenService` depends on for introspection-endpoint discovery. A reference-token-only BFF previously had an unsatisfiable singleton and failed DI validation at startup.
- Reference-token-only BFFs can now talk to a non-HTTPS IdP via the new `ReferenceTokenAuthOptions.RequireHttpsMetadata` (default `true`) instead of reaching into `SessionAuthenticationConfiguration`. Discovery requires HTTPS only while both the session and reference-token flags ask for it; either path opting out allows plain-http discovery.

## [0.2.0-rc.3] - 2026-06-14
### Updated
- Nuget packages up
### Added
- advanced.md and authentication.md docs: API versioning, endpoint grouping, and the "two auth layers" (identity gate vs. provider) guidance
- API versioning and auth composition tests
- `AddPortaReferenceTokenScheme`: registers opaque/reference tokens as ASP.NET auth scheme that populates `HttpContext.User`, so `RequireAuth()` and the principal gate work with no consumer-side auth code (shares one introspection/cache core with `ReferenceTokenAuthProvider`)
- Startup check that logs `Critical` when an endpoint requires an authenticated principal but no auth scheme is registered to populate `HttpContext.User`
### Fixed
- Predicate ambiguity handling for `.When()` endpoints sharing a route

## [0.1.0-rc.2] - 2026-06-14
### Added
- BFF Transformer (TransformerBase, PassThroughTransformer, AuthenticatedTransformer, MultiBackendTransformer, AggregatingTransformer)
- Multi-backend aggregation (AggregatingTransformer)
- Zero-code pass-through (PassThroughTransformer)
- Per-backend authentication policies (None, BasicAuth, BearerToken, TokenExchange)
- Fluent endpoint builder (WithAuth, WithTimeout, WithRetries, WithTokenExchange)
- Startup configuration validation
- Multiple auth providers
- Token lifecycle
- Session administration
- OIDC discovery
- Raw forwarding
- GraphQL support
- SSRF guard for token forwarding 
- Open-redirect protection
- Signed, time-limited return-URL tokens
- Constant-time Basic auth
- Secret-classified log redaction
- HA-ready, no sticky sessions
- Data Protection persistence
- Resilience
- OpenTelemetry
- Runnable demo
- UnitTests

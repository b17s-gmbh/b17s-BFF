# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

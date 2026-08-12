# Authentication

The BFF framework supports both user authentication (via `IAuthenticationProvider`) and backend authentication (via `IBackendAuthHandler`). For the OIDC pipeline (cookie + framework OIDC handler + server-side ticket store + token revocation + back-channel logout), see [oidc.md](./oidc.md).

## User Authentication Providers

The framework uses `IAuthenticationProvider` to expose user identity to transformers as `AuthenticationContext`. This is a *read* concern - the underlying authentication is owned by ASP.NET Core's auth schemes (cookie + OIDC, or JWT bearer, or reference token) configured at registration time.

### Built-in Providers

| Provider | Use Case | Token Refresh |
|----------|----------|---------------|
| `SessionAuthProvider` | Reads the cookie auth ticket populated by the framework's OIDC handler. Default when you call `AddPortaAuthentication`. | Yes (via `IAccessTokenRefreshService`) |
| `ReferenceTokenAuthProvider` | Reference token validation via introspection, in-pipeline only (`AddReferenceTokenAuthentication`) — resolves `AuthContext` but does **not** set `HttpContext.User`. Recommended for API-style callers. | No |
| `JwtBearerAuthProvider` | Inbound JWT validation via OIDC discovery / JWKS (opt-in fallback) | No |

For opaque tokens, prefer registering them as a **scheme** rather than provider-only:

| Scheme | Use Case | Token Refresh |
|--------|----------|---------------|
| `PortaReferenceToken` | The same introspection + binding + cache as `ReferenceTokenAuthProvider`, but registered as an ASP.NET auth scheme (`AddPortaReferenceTokenScheme`). It **sets `HttpContext.User`**, so `RequireAuth()` and the principal gate work for opaque tokens with no extra code. See [Two auth layers](#two-auth-layers-the-identity-gate-vs-the-provider). | No |

```csharp
// Program.cs
builder.Services.AddPortaCore();

// Introspection results are cached, so an IDistributedCache is required
// (Redis/Valkey in production; in-memory is fine for local dev).
builder.Services.AddDistributedMemoryCache();

builder.Services.AddPortaReferenceTokenScheme(options =>
{
    options.Authority = "https://idp.example.com";   // discovers the RFC 7662 introspection endpoint
    options.ClientId = "my-bff";                      // credentials used to call /introspect
    options.ClientSecret = builder.Configuration["ReferenceToken:ClientSecret"]!;
    options.ValidAudiences = ["api://my-bff"];        // reject tokens minted for another relying party
});

var app = builder.Build();

app.UseAuthentication();   // the PortaReferenceToken scheme introspects the token and sets HttpContext.User
app.UseAuthorization();

// The opaque token now gates endpoints like any other principal - no per-endpoint auth code.
// RequireAuthorizationByDefault is true, so this 401s without a valid, introspectable token:
app.MapPassThrough<ProductsResponse>()
    .FromGet("/api/products")
    .ToGet("https://products.internal/products")
    .Build();
```

`AddPortaReferenceTokenScheme` registers additively and becomes the default scheme **only when no other default is set**, so a reference-token-only BFF needs nothing more. In a multi-frontend BFF it does **not** clobber an existing default (e.g. the cookie default from `AddPortaAuthentication`, so browser `RequireAuthorization` still redirects to OIDC login) — register the other schemes too and add a policy scheme (or `ForwardDefaultSelector`) to pick per request, standard ASP.NET multi-scheme.

### SessionAuthProvider

After `AddPortaAuthentication` registers the framework's cookie + OIDC handlers, tokens live on the cookie auth ticket via `SaveTokens = true`. `SessionAuthProvider`:

- Calls `HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme)` to read the ticket.
- Returns `access_token`, `refresh_token`, `id_token`, `expires_at` plus claims as an `AuthenticationContext`.
- Delegates near-expiry refresh to `IAccessTokenRefreshService`, which acquires a per-user lock, calls the IdP's token endpoint, updates the ticket via `SignInAsync`, and patches the encrypted refresh token on session metadata so `TerminateSessionAsync(..., revokeTokens: true)` always targets the current token.

You don't typically construct or interact with `SessionAuthProvider` directly - it's resolved as `IAuthenticationProvider` in transformers.

### ReferenceTokenAuthOptions

`ReferenceTokenAuthProvider` validates inbound bearer tokens against the IdP's RFC 7662 introspection endpoint and caches results in `IDistributedCache` (typically Redis) to avoid re-introspecting on every request.

#### Inbound token extraction

| Option | Default | Description |
|--------|---------|-------------|
| `TokenHeaderName` | `Authorization` | Header to read the inbound token from. |
| `TokenPrefix` | `Bearer ` | Prefix stripped from the header value before introspection. |

#### Introspection endpoint client

| Option | Default | Description |
|--------|---------|-------------|
| `Authority` | - | OIDC authority URL - used to discover the introspection endpoint. |
| `ClientId` | - | Client ID used when authenticating to the introspection endpoint. |
| `ClientSecret` | - | Client secret used when authenticating to the introspection endpoint. |
| `UseBasicAuthForIntrospection` | `true` | Send credentials via HTTP Basic auth. When `false`, `client_id` / `client_secret` are sent in the request body. |
| `TokenTypeHint` | `access_token` | Optional `token_type_hint` parameter (RFC 7662 §2.1). |

The introspection `HttpClient` uses the standard resilience pipeline (retry + circuit breaker + timeouts; attempt timeout 10 s, total request timeout 30 s by default). Override it via the optional `configureResilience` parameter:

```csharp
builder.Services.AddReferenceTokenAuthentication(
    options => { /* ... */ },
    configureResilience: r => r.AttemptTimeout.Timeout = TimeSpan.FromSeconds(5));
```

#### Token binding - audience / issuer / client_id

Without these checks, **any active token issued by the same authority for any other relying party** would be accepted by this BFF (RFC 7662 audience-confusion vulnerability). Defaults are strict; loosen only when you fully trust the introspection endpoint and understand the consequences.

| Option | Default | Description |
|--------|---------|-------------|
| `ValidateAudience` | `true` | Validate the `aud` / `client_id` claim on introspection responses. |
| `ValidAudiences` | `[]` | Expected audience values. When non-empty and `ValidateAudience` is `true`, the introspection response's `aud` claim must match one of these values. |
| `ValidClientIds` | `[]` | Allow-list of `client_id` values that may have minted accepted tokens. Use as an alternative or supplement to `ValidAudiences` when the IdP returns `client_id` but no `aud`. |
| `ValidateIssuer` | `true` | Validate the `iss` claim on introspection responses. |
| `ValidIssuers` | `[]` | Expected issuer values. When empty, defaults to comparing against `Authority`. |

#### Cache

| Option | Default | Description |
|--------|---------|-------------|
| `DefaultCacheDuration` | `5 minutes` | Cache duration when the introspection response has no `exp` claim. |
| `MaxCacheDuration` | `1 hour` | Upper bound on cache duration regardless of token lifetime. |
| `NegativeCacheDuration` | `30 seconds` | How long an *inactive* introspection result is cached before re-introspecting. Trade-off below. |

#### `NegativeCacheDuration` trade-off

When the IdP returns `active: false`, the provider caches that result for
`NegativeCacheDuration` so a stream of requests carrying the same revoked /
expired / unknown token doesn't hammer the introspection endpoint. Only that
definitive verdict is negative-cached: if introspection *fails* (IdP error,
unreachable endpoint, malformed response), the request is rejected without
writing a cache entry, so a valid token authenticates again as soon as the
IdP recovers rather than staying locked out for `NegativeCacheDuration`. This is
necessary - without it, an attacker (or a buggy client) replaying one bad
token can DoS the IdP - but it has a security cost: a token revoked at the
IdP keeps being accepted "as still revoked" for at most this duration before
the next live introspection runs. That is *not* a security issue per se
(rejected stays rejected), but for a token that **was active and is then
revoked**, the previous *positive* result remains cached until its own
positive TTL expires - so revocation latency is bounded by
`min(DefaultCacheDuration, MaxCacheDuration, token's own exp)`, not by
`NegativeCacheDuration`.

Set lower (e.g. `5 seconds`) if you need IdP-side revocation to take effect
faster and can absorb the extra introspection traffic. Set higher
(`60 seconds`, `120 seconds`) if your IdP is rate-limited or expensive
(commercial per-call pricing) and you accept that an active token remains
usable for up to `DefaultCacheDuration` after revocation regardless.

The introspection cache key is always the SHA-256 hash of the access token - keys look like `introspection_{SHA256-hex}`, never `introspection_{raw-token}`. This prevents anyone with read access to the cache (co-tenants on a shared Redis instance, operators running `KEYS`/`SCAN`/`MONITOR`, anyone who can read a backup or replica) from enumerating live bearer tokens and replaying them against a resource server. Both reads and invalidations use the same hashed key, so this is transparent to callers and not configurable.

### JWT Bearer Authentication (opt-in)

Reference tokens are the recommended default in a BFF context. In a BFF, you're already making round-trips to the IdP for token refresh, so JWT's stateless-validation advantage doesn't apply — and reference tokens give you immediate revocation and a smaller payload. Use `JwtBearerAuthProvider` when one of these doesn't fit:

- Your IdP doesn't expose an introspection endpoint.
- You're integrating with a B2B partner or third-party API that hands callers signed JWTs.
- You need stateless validation at the edge (no introspection round-trip per request).

#### Registration

```csharp
builder.Services.AddPortaJwtAuthentication(options =>
{
    options.Authority = "https://auth.example.com";
    options.ValidAudiences = ["my-porta"];

    // Optional overrides
    // options.ValidIssuers = ["https://auth.example.com"]; // defaults to OIDC metadata issuer
    // options.ClockSkew = TimeSpan.FromSeconds(30);
});
```

`AddPortaJwtAuthentication` can be combined with `AddPortaAuthentication` (or its `AddPortaOidcAuth` alias), `AddReferenceTokenAuthentication`, and `AddPortaAuthProvider<T>`. See [Combining authentication providers](#combining-authentication-providers) below for resolution semantics.

The JwtBearer handler binds from the composed options pipeline, so `services.Configure<JwtBearerAuthOptions>(...)` / `PostConfigure<JwtBearerAuthOptions>(...)` registered before or after this call (e.g. injecting the authority from a secret store) is honored.

#### How signing keys are managed

Signing keys come from the OIDC discovery document at `{Authority}/.well-known/openid-configuration` and the JWKS endpoint it points to. Validation is handled by ASP.NET Core's `AddJwtBearer` handler: keys are cached in memory and refreshed on the schedule of its built-in `Microsoft.IdentityModel.Protocols.OpenIdConnect.ConfigurationManager` (its default cadence; an unknown `kid` also triggers an out-of-band refresh). Key rotation is handled automatically.

#### Validation defaults

| Option | Default | Notes |
|--------|---------|-------|
| `ValidateIssuer` | `true` | Falls back to the issuer in OIDC metadata when `ValidIssuers` is empty. |
| `ValidateAudience` | `true` | At least one entry in `ValidAudiences` must match the token's `aud`. |
| `ValidateLifetime` | `true` | Honors `exp`/`nbf` plus `ClockSkew`. |
| `RequireHttpsMetadata` | `true` | Disable only for local dev against a non-HTTPS IdP. |
| `ClockSkew` | `30 seconds` | Allowed drift when validating `exp`/`nbf`. |

#### Backend authentication interplay

JWT vs reference tokens is an *inbound* concern only. Once validated, the token sits on `AuthContext.AccessToken` and `BackendAuthPolicies.BearerToken` forwards it downstream unchanged - your backends see the same shape regardless of which inbound provider you use. For backends that need a different token (different audience, different IdP), keep using `BackendAuthPolicies.TokenExchange`.

#### Limitations

- `RefreshAsync` is a no-op - JWTs are stateless and can't be refreshed server-side. Clients must obtain new tokens before expiry.
- `InvalidateAsync` is a no-op - JWTs can't be revoked at the BFF. If immediate revocation matters, prefer reference tokens.

### Custom Authentication Provider

Implement `IAuthenticationProvider` for custom authentication scenarios (API keys, HMAC, custom JWTs, etc.):

```csharp
public class ApiKeyAuthProvider : IAuthenticationProvider
{
    private readonly IApiKeyValidator _validator;

    public ApiKeyAuthProvider(IApiKeyValidator validator) => _validator = validator;

    public async Task<AuthenticationContext> GetAuthContextAsync(
        HttpContext context, CancellationToken cancellationToken = default)
    {
        var apiKey = context.Request.Headers["X-Api-Key"].FirstOrDefault();
        if (string.IsNullOrEmpty(apiKey))
            return new AuthenticationContext(); // Not authenticated

        var keyInfo = await _validator.ValidateAsync(apiKey, cancellationToken);
        if (keyInfo == null)
            return new AuthenticationContext(); // Invalid key

        return new AuthenticationContext
        {
            AccessToken = apiKey,
            Claims =
            {
                ["api_key_id"] = [keyInfo.KeyId],
                ["tenant_id"] = [keyInfo.TenantId]
            }
        };
    }

    public Task<AuthenticationContext?> RefreshAsync(
        AuthenticationContext current, CancellationToken cancellationToken = default)
        => Task.FromResult<AuthenticationContext?>(null); // API keys don't refresh

    public Task InvalidateAsync(HttpContext context, CancellationToken cancellationToken = default)
        => Task.CompletedTask; // Nothing to invalidate for stateless API keys
}
```

Register your custom provider:

```csharp
// Simple registration
builder.Services.AddPortaAuthProvider<ApiKeyAuthProvider>();

// Or with factory for explicit construction
builder.Services.AddPortaAuthProvider<ApiKeyAuthProvider>(sp =>
    new ApiKeyAuthProvider(sp.GetRequiredService<IApiKeyValidator>()));
```

> **A custom provider does not satisfy `RequireAuthorization` by itself — read the next section before shipping it.** Left at the default, an endpoint behind such a provider returns `401` *before your provider ever runs*.

### Two auth layers: the identity gate vs. the provider

Porta enforces authentication at **two** distinct points, and conflating them is the most common BFF footgun:

1. **The ASP.NET identity gate — `HttpContext.User`.** Every Porta endpoint stamps `RequireAuthorization()` at `.Build()` unless told otherwise (`RequireAuthorizationByDefault` defaults to `true`; override per endpoint with `.RequireAuth("policy")` / `.AllowAnonymous()`). That requirement is enforced by ASP.NET's authorization middleware **before** the endpoint runs, and re-checked inside Porta's handler as defense-in-depth. It passes only if `HttpContext.User.Identity.IsAuthenticated` is `true` — which is set exclusively by a registered **ASP.NET authentication scheme**.
2. **The Porta provider — `AuthContext`.** Your `IAuthenticationProvider.GetAuthContextAsync` runs **inside** the endpoint handler, *after* the identity gate, and resolves the access token + claims used for **backend** calls. It does **not** populate `HttpContext.User`.

So whether the gate and the provider line up depends on how your auth is registered:

| Auth mechanism | Registers an ASP.NET scheme? | Sets `HttpContext.User`? | Default `RequireAuthorization` works? |
| --- | --- | --- | --- |
| `AddPortaAuthentication` (cookie + OIDC) | ✅ | ✅ | ✅ — no extra action |
| `AddPortaJwtAuthentication` (JWT bearer) | ✅ | ✅ | ✅ — no extra action |
| **`AddPortaReferenceTokenScheme`** (opaque token) | ✅ | ✅ | ✅ — no extra action |
| `AddReferenceTokenAuthentication` (provider only) | ❌ | ❌ | ❌ — gate 401s first |
| Custom `IAuthenticationProvider` (API key, HMAC, …) | ❌ | ❌ | ❌ — gate 401s first |

For the two ❌ rows the provider authenticates **in-pipeline only**, so the default identity gate short-circuits with `401` before the provider is consulted — even when the request carries a perfectly valid token. (Porta logs a `Critical` startup warning when an endpoint requires a principal but no scheme is registered, so this doesn't stay silent.) You have two ways to fix it:

**Option A — drop the gate, authenticate in-pipeline.** Mark the endpoints `.AllowAnonymousWithOptionalAuth()` so the request reaches the handler and your provider runs and populates `AuthContext` for the backend call:

```csharp
app.MapPassThrough<DataResponse>()
    .FromGet("/api/data")
    .ToGet("https://api.internal/data")
    .AllowAnonymousWithOptionalAuth()   // skip the ASP.NET identity gate; the provider runs in-pipeline
    .Build();
```

`.AllowAnonymousWithOptionalAuth()` means "no ASP.NET principal required", **not** "no auth" — the provider still resolves credentials for the transformer and (with an `optional: true` backend policy) the backend call. Plain `.AllowAnonymous()` will **not** work here: it is credential-blind — the provider is never consulted and `AuthContext` stays empty. If you also need to *reject* anonymous callers, enforce it in-pipeline: a transformer whose `RequiresAuthentication` returns `true` 401s when `context.UserId` (i.e. the provider's `AuthContext`) is empty. A zero-code `MapPassThrough` does **not** do this, so don't rely on the endpoint mode alone to protect a passthrough.

**Option B — register a real scheme (recommended when you want `RequireAuthorization` to work).** A scheme populates `HttpContext.User`, so the identity gate passes normally, your `IAuthenticationProvider` reads the already-validated principal/token for backend forwarding, and `.RequireAuth("policy")`, fallback policies, and group conventions all behave as a vanilla ASP.NET app expects.

For **opaque / reference tokens**, this is built in — swap `AddReferenceTokenAuthentication` for `AddPortaReferenceTokenScheme`:

```csharp
builder.Services.AddPortaReferenceTokenScheme(options =>
{
    options.Authority = "https://idp.example.com";
    options.ValidAudiences = ["api://my-bff"];
});

// ...then nothing else changes — the opaque token gates endpoints like any other principal:
app.MapRawForward()
    .FromGet("/api/{**catch-all}")
    .ToGet("https://logic.internal/api/{**catch-all}")
    .RequireAuth()          // works: the scheme introspected the token and set HttpContext.User
    .Build();
```

The `PortaReferenceToken` scheme runs the same introspection, audience/issuer binding, and distributed (positive + negative) cache as the provider — the token is introspected at most once per request — and returns a principal carrying the introspection claims. It composes with cookie/OIDC and JWT bearer via standard multi-scheme selection (a policy scheme or `ForwardDefaultSelector`); the only thing that changes between credential types is the `AddPorta…` registration line, so the BFF's forwarding code is identical either way. For credential types Porta doesn't ship (HMAC, mTLS-derived identity, …), implement a standard ASP.NET Core `AuthenticationHandler` the same way.

> **Don't put authorization on a `MapGroup`** to cover Porta endpoints — Porta's per-endpoint stamp wins, and an endpoint that resolves to anonymous emits `AllowAnonymous()` that overrides the group requirement. See [Advanced Topics → Grouping endpoints](advanced.md#grouping-endpoints-with-mapgroup).

### Combining authentication providers

Multiple authentication providers can be registered side-by-side. A typical deployment accepts browser users via a session cookie, mobile/SPA callers via a JWT, and service-to-service traffic via an API key - all on the same endpoints:

```csharp
builder.Services
    .AddPortaAuthentication(config)                       // session (cookie + OIDC)
    .AddPortaJwtAuthentication(opt => { /* ... */ })      // JWT bearer
    .AddPortaAuthProvider<ApiKeyAuthProvider>();          // custom
```

Registered providers are composed at resolution time into a single `IAuthenticationProvider` with the following semantics:

- **Resolution order is registration order.** Each request is offered to providers in the order they were registered. The first provider whose `GetAuthContextAsync` returns `IsAuthenticated = true` wins; the rest are not called for that request. Register cheap, header-based providers (JWT, API key) before expensive ones if they're more common on your traffic profile.
- **Refresh routes to the originating provider.** The winning provider's `Scheme` is stamped onto the returned `AuthenticationContext`. When `RefreshAsync` is later called on that context, the composite routes it back to the same provider. Providers that don't support refresh (JWT, reference tokens, most API keys) return `null` as before.
- **Logout fans out to every provider.** `InvalidateAsync` is called on all registered providers so that every credential surface is cleared (session sign-out, reference-token cache eviction, etc.). Each provider's invalidation is independent - a failure in one is logged and does not block the others.
- **Mixed-credential requests are logged at Debug.** If a request carries both an `Authorization` header and a cookie-auth ticket, the composite emits an event-id `13610` Debug log naming the scheme that matched. Useful for diagnosing "why did this request authenticate as X instead of Y" without runtime cost in production.

### AuthenticationContext Properties

| Property | Description |
|----------|-------------|
| `AccessToken` | Primary access token (determines `IsAuthenticated`) |
| `RefreshToken` | Token for refreshing access (OIDC) |
| `IdToken` | OIDC ID token |
| `ExpiresAt` | Token expiration time |
| `Claims` | User claims dictionary |
| `Headers` | Additional auth headers to forward |
| `ServiceTokens` | Per-service tokens (for different audiences) |
| `IsAuthenticated` | True if `AccessToken` is present |
| `IsExpiredWithSkew(skew)` | Method (not a property): true if the token is expired or within `skew` of expiry. Pass `PortaCoreOptions.TokenRefreshSkew` so all layers agree on staleness. An overload takes an explicit `TimeProvider` for tests. |
| `Scheme` | Identifier of the provider that issued this context. Set automatically when multiple providers are registered; used to route `RefreshAsync` back to the originating provider. |

### Accessing Claims in Transformers

Inside a transformer, the authenticated user's claims are available through `TransformerContext`:

```csharp
public override async Task<MyResponse> TransformAsync(TransformerContext context)
{
    var userId = context.UserId;                  // standard OIDC `sub` claim
    var tenantId = context.GetClaim("tenant_id"); // first value of any claim by name
    var roles = context.GetClaims("role");        // every value of a repeated claim
    // ...
}
```

`UserId` is shorthand for `GetClaim("sub")` and is the value the built-in transformer base classes check against when `RequireAuth()` / `RequiresAuthentication` is set.

A single claim type can carry multiple values (for example, several `role` claims). `GetClaim(name)` returns the **first** value (or `null` when absent); `GetClaims(name)` returns **every** value as an `IReadOnlyList<string>` (empty when absent). Underlying storage is `AuthenticationContext.Claims`, a `Dictionary<string, string[]>`.

For domain-specific claims that you reach for often, define your own extension methods to keep call sites readable:

```csharp
public static class MyTransformerContextExtensions
{
    public static string? TenantId(this TransformerContext ctx) => ctx.GetClaim("tenant_id");
    public static string? CustomUserId(this TransformerContext ctx) => ctx.GetClaim("custom_id");
}

// Usage:
var tenant = context.TenantId();
```

This keeps the library generic while letting any consumer add their own typed accessors without forking or configuration plumbing.

## Backend Authentication

Backend auth handlers apply authentication to outgoing requests to backend services.

### Built-in Policies

| Policy | Description | Requires User Identity |
|--------|-------------|------------------------|
| `None` | No authentication | No |
| `BasicAuth` | HTTP Basic auth with configured credentials | No |
| `ApiKey` | Fixed API key from configuration. Default `Authorization: Bearer <token>`; the scheme is configurable (`Scheme`), or send the raw key in a custom header (`HeaderName`, e.g. `X-Api-Key`). Per-backend keys via `BackendService:ApiKeys`, fail-closed like BasicAuth. | No |
| `ClientCredentials` | OAuth2 client-credentials grant (RFC 6749 §4.4): the BFF mints an access token for its **own** machine-to-machine identity and sends it as a Bearer credential. Configured under `BackendService:ClientCredentials` (`TokenEndpoint`, `ClientId`, `ClientSecret` required; optional `Scope`/`Audience`) — deliberately separate from `SessionAuthentication`. Tokens are cached process-wide until 60s before expiry; failures are never cached. Per-backend clients via `BackendService:ClientCredentialsBackends`, fail-closed (as a 5xx-class config error) unless `AllowGlobalClientCredentialsFallback` is set. | No |
| `BearerToken` | Forward user's bearer token | Yes |
| `TokenExchange` | Exchange user token for backend-specific token (RFC 8693) - requires an audience | Yes |

> **TokenExchange requires an audience.** Prefer `.WithTokenExchange(audience)` on the endpoint builder — this rejects a null/blank audience immediately at configuration time. If you must select it via `.WithBackendAuth(BackendAuthPolicies.TokenExchange)` (no inline audience), configure a fallback via `BackendServiceOptions.DefaultTokenExchangeAudience` or per-backend `BackendServiceOptions.TokenExchangeAudiences[backendName]`. When an endpoint mapped at startup selects the policy with no resolvable audience source, Porta **fails fast at startup**. The runtime guard remains as a backstop for cases the startup check can't see (e.g. a backend name rewritten via `ModifyRequest`): there a missing audience surfaces as a server-side **configuration error (500-class)**, not a user `401` — a missing audience is operator misconfiguration, not a credential rejection.

The built-in `TokenExchange` handler inherits the rest of its wiring from your session configuration: the IdP **token endpoint** is resolved from OIDC discovery on `SessionAuthentication.Authority`, and the **client credentials** come from `SessionAuthentication.ClientId`/`ClientSecret`. You only supply the audience. Exchanged tokens are cached per session by `IApiTokenService`, which stores them in `HttpContext.Session` - enable ASP.NET Core session (`AddSession()` + `UseSession()`) or every request performs a fresh exchange.

### Refreshing the user token on a backend 401

When a backend returns `401` on a user-token policy, Porta treats it as a stale-token signal: it force-refreshes the user's session access token against the IdP and retries the call **once** with the rotated token. This is **on by default** - opt out globally with `PortaCore:RefreshBackendTokenOn401 = false`.

The `ClientCredentials` policy has the analogous behavior under the same flag: on a backend `401` the cached machine-to-machine token is discarded and the call retried **once** with a freshly minted token (covers revoked tokens and rotated signing keys). A second `401` surfaces unchanged - a fresh token being rejected means the problem is not staleness. `BasicAuth`/`ApiKey`/`None` are never retried; re-minting cannot fix static credentials.

### Claims refresh on token refresh

Every successful token refresh also updates the session (cookie) principal's **claims** from the new `id_token`, when the IdP returns one with the refresh response - so IdP-side changes (roles granted or revoked, renamed users) propagate to the BFF without a re-login. On by default; opt out with `PortaCore:RefreshClaimsFromIdToken = false` to keep login-time claims for the whole session.

Semantics:

- For every claim **type** the new `id_token` carries, the session's claims of that type are replaced with the new values - multi-value types (roles) are replaced as a set, so revoked values disappear.
- Types the new `id_token` does **not** carry stay untouched: IdPs commonly issue leaner id_tokens on refresh than at login, and treating absence as revocation would silently strip login-only claims. To *revoke* a claim, the IdP must re-assert the type with the remaining values (an empty set cannot be expressed; model "no roles" as a role claim with a sentinel or opt for short session lifetimes).
- OIDC protocol and login-time claims (`iss`, `aud`, `nonce`, `auth_time`, `amr`, `acr`, `sid`, ...) are never copied. Principals built with ASP.NET's default inbound claim mapping are handled - a raw `role` in the id_token updates the mapped `ClaimTypes.Role` the cookie actually carries.
- Per OIDC Core §12.2 the new id_token's `iss` and `sub` must match the session's previous id_token (falling back to the principal's subject). On mismatch - or an unparsable token - the claims update is skipped with a warning (`EventId 14406`) and the rotated tokens are stored normally. The signature is not re-validated: the token arrived over the BFF's own client-authenticated TLS channel to the token endpoint, the same trust that accepts the rotated access token.

Note the propagation boundary: the update lands in the cookie ticket via `SignInAsync`, so **subsequent** requests see the new claims. The request that triggered the refresh keeps its already-populated `HttpContext.User` / `AuthContext` for the remainder of its pipeline.

```csharp
// Nothing to enable - this just works for BearerToken / TokenExchange backends:
app.MapPassThrough<OrderResponse>()
    .FromGet("/api/orders/{id}")
    .ToGet("https://orders.internal/orders/{id}")
    .WithBackendAuth(BackendAuthPolicies.BearerToken)
    .RequireAuth()
    .Build();

// Opt out globally:
builder.Services.AddPortaCore(o => o.RefreshBackendTokenOn401 = false);
```

- **On by default; config opt-out.** Set `PortaCoreOptions.RefreshBackendTokenOn401 = false` (or `PortaCore:RefreshBackendTokenOn401` in config) to disable. Opt out if a backend legitimately returns `401` for reasons unrelated to a stale token.
- **Bounded.** Exactly one IdP refresh + one retry per request. A second `401` is returned as-is - so the caller still sees `502` under the default mapper, or `401` if you've registered `PassThroughBackendErrorMapper`. The retry is skipped entirely when the token doesn't actually rotate (no refreshable session, refresh failed), so it never loops.
- **User-token policies only.** Only `BearerToken`/`TokenExchange` trigger it; `BasicAuth`/`None` are never affected, since refreshing the user token can't fix their credentials.
- **Concurrency-safe across aggregation.** When an `AggregatingTransformer` fans out to several user-token backends in parallel and more than one returns `401`, the refresh is serialized and deduplicated: **exactly one** IdP refresh and one cookie rewrite, then each failed leg retries with the rotated token.
- **Refreshable inbound only.** Meaningful when the request authenticated via a refreshable session (cookie + OIDC). For non-refreshable inbound auth (inbound JWT, reference tokens) there's nothing to refresh, so the `401` simply propagates.

### Custom Backend Auth Handler

Implement `IBackendAuthHandler` to add custom authentication policies. The `BackendAuthContext` passed to the handler carries the user's access token (`AccessToken`), the authenticated user's claims (`Claims`, first value wins for repeated claim types; empty for anonymous requests), the outgoing `BackendRequest`, and the request's `CancellationToken`:

```csharp
public class HmacAuthHandler : IBackendAuthHandler
{
    public string PolicyName => "HmacAuth";

    public Task ApplyAuthAsync(HttpRequestMessage request, BackendAuthContext context)
    {
        var signature = ComputeHmacSignature(request);
        request.Headers.Add("X-Signature", signature);
        request.Headers.Add("X-Timestamp", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString());
        return Task.CompletedTask;
    }
}

// Registration
builder.Services.AddPortaCore();
builder.Services.AddPortaAuthHandler<HmacAuthHandler>();

// With factory for complex dependencies
builder.Services.AddPortaAuthHandler<ApiKeyAuthHandler>(sp =>
    new ApiKeyAuthHandler(sp.GetRequiredService<IConfiguration>()["ApiKeys:Partner"]));

// Register multiple handlers at once
builder.Services.AddPortaAuthHandlers(
    typeof(HmacAuthHandler),
    typeof(ApiKeyAuthHandler),
    typeof(ClientCredentialsAuthHandler));
```

### Usage in Endpoints

```csharp
app.MapTransformer<PartnerTransformer, Response>()
    .FromGet("/api/partner-data")
    .ToGet("https://partner-api.example.com/data")
    .WithBackendAuth("HmacAuth")  // Uses custom handler
    .Build();
```

## Per-Backend Authentication

Multi-backend transformers support per-backend authentication configuration:

```csharp
app.MapTransformer<MyTransformer, MyResponse>()
    .FromGet("/api/aggregated")
    .ToBackends(b => b
        .ToPost("UserInfo", "https://users.internal/userinfo").WithAuth(BackendAuthPolicies.BasicAuth)
        .ToGet("Products", "https://products.internal/products").WithAuth(BackendAuthPolicies.BearerToken))
    .Build();
```

### Per-Backend Modifiers

These chain off each `ToGet/ToPost/...` in the `ToBackends(configure => ...)` builder and apply to the backend they follow (the same names also work as tuple extensions on the array form of `ToBackends`):

| Method | Description |
|--------|-------------|
| `.WithAuth(policy)` | Apply a specific authentication policy |
| `.WithUserToken()` | Forward user's OAuth token to trusted internal services |
| `.WithTokenExchange(audience)` | Exchange user token for backend-specific token |
| `.WithTimeout(timespan)` | Set custom timeout (chainable with above) |
| `.WithRetries(maxAttempts)` | Enable automatic retries for transient failures |

### Fallback Authentication

Use `WithBackendAuth()` to set a default auth policy for backends without explicit configuration:

```csharp
app.MapTransformer<MyTransformer, MyResponse>()
    .FromGet("/api/data")
    .WithBackendAuth(BackendAuthPolicies.BasicAuth)  // Fallback
    .ToBackends(b => b
        .ToGet("Backend1", $"{url1}/data")                                    // Uses fallback
        .ToGet("Backend2", $"{url2}/data").WithAuth(BackendAuthPolicies.BearerToken)  // Explicit
        .ToGet("Backend3", $"{url3}/public"))                                 // Uses fallback
    .Build();
```

## Trusted Hosts

When using `.WithUserToken()`, the user's OAuth token is forwarded directly to the backend. This should **only** be used with trusted internal services.

### Configuration

```json
{
  "PortaCore": {
    "TrustedHosts": [
      "https://api.internal.company.com",
      "https://*.internal.company.com",
      "https://api.company.com:8443"
    ]
  }
}
```

### Startup Validation

If a backend using `WithUserToken()` is not in the trusted hosts list, the application **fails to start**:

```
InvalidOperationException: Backend endpoint 'InternalApi' URL 'https://untrusted.example.com/api'
is not in the trusted hosts list. WithUserToken() forwards the user's OAuth token and should only
be used with trusted internal services. Add the host to PortaCore:TrustedHosts or use a
different auth policy.
```

## Token Services

The framework provides provider-agnostic token services for token refresh, revocation, exchange, and caching.

### Provider-Agnostic Usage

All token services support explicit configuration parameters:

```csharp
// Token refresh with explicit options
var refreshOptions = new TokenRefreshOptions
{
    TokenEndpoint = "https://auth.example.com/oauth/token",
    ClientId = "my-client",
    ClientSecret = "my-secret",
    Scope = "openid profile"
};
var tokens = await tokenRefreshService.RefreshAsync(refreshToken, refreshOptions);

// Token revocation with explicit options
var revocationOptions = new TokenRevocationOptions
{
    RevocationEndpoint = "https://auth.example.com/oauth/revoke",
    ClientId = "my-client",
    ClientSecret = "my-secret"
};
await tokenRevocationService.RevokeTokenAsync(accessToken, revocationOptions, "access_token");
```

### OIDC-Configured Usage

When using OIDC authentication, simpler overloads use injected configuration:

```csharp
var tokens = await tokenRefreshService.RefreshAsync(refreshToken);
await tokenRevocationService.RevokeTokenAsync(accessToken);
```

### Token Service Interfaces

| Interface | Purpose |
|-----------|---------|
| `ITokenRefreshService` | Refresh OAuth tokens against the IdP's token endpoint |
| `IAccessTokenRefreshService` | Returns the current access token for the request, transparently refreshing if near expiry. Wraps `ITokenRefreshService` with per-user locking and ticket-store updates. Use this from inside transformers / backend handlers; use `ITokenRefreshService` only when you have a refresh token in hand outside the cookie-auth pipeline. |
| `ITokenRevocationService` | Revoke tokens at the IdP's revocation endpoint (RFC 7009) |
| `ITokenExchangeService` | Exchange the user's access token for a backend-specific token (RFC 8693) |
| `IApiTokenService` | Cache and manage API-specific tokens (token-exchange results) |

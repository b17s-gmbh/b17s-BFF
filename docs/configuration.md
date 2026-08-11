# Configuration

## Service Registration

The BFF library uses a modular registration approach with opt-in authentication.

### AddPortaCore() - Core Services

Registers the minimum required services for transformer-based API aggregation. **This is always required.**

```csharp
builder.Services.AddPortaCore(options => {
    // Trusted hosts for user token forwarding (WithUserToken())
    options.TrustedHosts = ["https://api.example.com", "https://*.internal.example.com"];

    // Default timeout for backend calls (default: 30 seconds)
    options.DefaultTimeout = TimeSpan.FromSeconds(30);

    // App-wide ceiling for per-endpoint .WithRetries(n). Each endpoint retries
    // min(n, MaxRetryAttempts) times; endpoints that never call .WithRetries(...)
    // do not retry. Set to 0 to disable retries app-wide, including for endpoints
    // that opt in via .WithRetries(...) (default: 3).
    options.MaxRetryAttempts = 3;

    // Refresh the user token and retry once on a backend 401 (default: true)
    options.RefreshBackendTokenOn401 = true;

    // Require authorization by default (default: true)
    options.RequireAuthorizationByDefault = true;

    // Enable OpenTelemetry instrumentation (default: true)
    options.EnableTelemetry = true;

    // Cap on backend response body characters written to Trace logs (default: 512).
    // -1 = unlimited; 0 = disable body logs entirely. See docs/telemetry.md.
    options.MaxBodyLogLength = 512;

    // Max bytes BFF will buffer from a backend response before failing the call
    // with InvalidResponse (default: 10 MiB). Applies to JSON/XML/form
    // deserialization. <= 0 disables the cap. See docs/raw-forwarding.md for the
    // separate raw-forward cap.
    options.MaxBackendResponseBytes = 10 * 1024 * 1024;

    // Raw-forward egress ceiling. Separate from MaxBackendResponseBytes because
    // raw forwards (file downloads, etc.) legitimately stream larger payloads
    // (default: 100 MiB). <= 0 disables the cap.
    options.MaxRawForwardResponseBytes = 100L * 1024 * 1024;

    // Max time between successive reads from a raw-forward backend before the
    // call is aborted (default: 30s). Defeats slow-loris backends that dribble
    // bytes to pin a BFF worker.
    options.RawForwardReadIdleTimeout = TimeSpan.FromSeconds(30);

    // Clock skew applied when deciding whether an access token is "near expiry"
    // and should be proactively refreshed (default: 60 seconds). Used by both
    // AccessTokenRefreshService and the ApiTokenService cache.
    options.TokenRefreshSkew = TimeSpan.FromSeconds(60);

    // Whether to log raw IdP error response bodies on token exchange/refresh/
    // revocation/introspection failures (default: false). Verbose IdPs frequently
    // echo the submitted refresh token / client secret / PII back inside the error
    // JSON - leave this off in production.
    options.LogIdpErrorBodies = false;

    // Max bytes of an IdP error response body that may be logged when
    // LogIdpErrorBodies is enabled (default: 512). Larger bodies are truncated.
    options.IdpErrorBodyMaxBytes = 512;

    // Default raw-forward header pass-through allow-list. By default the BFF strips
    // Cookie, Authorization, and X-Forwarded-* headers from raw-forwarded requests.
    // Add header names here to opt them back in globally (see docs/raw-forwarding.md).
    // options.DefaultRawForwardHeaderPassThrough.AllowedHeaders.Add("X-Foo");
});
```

Or bind from configuration:

```csharp
builder.Services.AddPortaCore(builder.Configuration);
```

```json
// appsettings.json
{
  "PortaCore": {
    "TrustedHosts": ["https://api.example.com"],
    "DefaultTimeout": "00:00:30",
    "MaxRetryAttempts": 3,
    "RefreshBackendTokenOn401": true,
    "RequireAuthorizationByDefault": true,
    "EnableTelemetry": true,
    "MaxBodyLogLength": 512,
    "MaxBackendResponseBytes": 10485760,
    "MaxRawForwardResponseBytes": 104857600,
    "RawForwardReadIdleTimeout": "00:00:30",
    "TokenRefreshSkew": "00:01:00",
    "LogIdpErrorBodies": false,
    "IdpErrorBodyMaxBytes": 512
  }
}
```

**What it registers:**
- Backend caller infrastructure (HttpClients with resilience)
- Backend auth handler registry with built-in handlers (`None`, `BearerToken`, `BasicAuth`, `TokenExchange`)
- Trusted host validation for secure token forwarding
- Transformer routing support

### AddPortaAuthentication() - OIDC Authentication (Opt-in)

Adds the full BFF OIDC pipeline: framework cookie + OpenIdConnect handlers, server-side ticket store, automatic refresh, RFC 7009 token revocation, and admin/back-channel session management. **Only call this if you need user authentication.**

```csharp
builder.Services.AddPortaAuthentication(builder.Configuration);
```

```json
// appsettings.json - section name defaults to "SessionAuthentication"
{
  "SessionAuthentication": {
    "Authority": "https://auth.example.com",
    "RequireHttpsMetadata": true,
    "ClientId": "my-porta",
    "ClientSecret": "secret",
    "Scope": "openid profile email api",
    "CookieName": "__Porta",
    "UsePkce": true,
    "QueryUserInfoEndpoint": true,
    "SessionTimeoutInMin": 60,
    "TokenExchangeStrategy": "default",
    "Cookie": {
      "SameSite": "Lax",
      "HttpOnly": true,
      "SecurePolicy": "Always",
      "ExpireTimeSpanMinutes": 60,
      "SlidingExpiration": false
    },
    "Challenge": {
      "Mode": "Auto"
    },
    "DataProtection": {
      "ApplicationName": "my-porta",
      "KeyLifetimeDays": 90
    },
    "Resilience": {
      "EnableRetry": true,
      "MaxRetryAttempts": 3,
      "InitialDelaySeconds": 1.0,
      "UseJitter": true,
      "EnableCircuitBreaker": true,
      "CircuitBreakerFailureRatio": 0.5,
      "CircuitBreakerSamplingDurationSeconds": 30.0,
      "CircuitBreakerMinimumThroughput": 10,
      "CircuitBreakerBreakDurationSeconds": 30.0,
      "RequestTimeoutSeconds": 10.0
    },
    "SessionKeys": {
      "Prefix": "porta"
    }
  }
}
```

Custom section name:

```csharp
builder.Services.AddPortaAuthentication(builder.Configuration, configSectionName: "MyAuth");
```

**Section name duality - `SessionAuthentication` vs `OidcAuth`.** `AddPortaAuthentication(IConfiguration)` defaults to the `"SessionAuthentication"` section and binds it onto `SessionAuthenticationConfiguration`. The `AddPortaOidcAuth(IConfiguration)` counterpart defaults to `"OidcAuth"` (the `OidcAuthOptions.SectionName` constant) and binds the same shape onto `OidcAuthOptions : SessionAuthenticationConfiguration`. Pick one section name in your `appsettings.json` and call the matching overload; the two are interchangeable, but the BFF will not read both. New code should prefer `AddPortaAuthentication` with the `SessionAuthentication` section.

**Alternate entry point.** `AddPortaOidcAuth` (taking either `Action<OidcAuthOptions>` or `IConfiguration`) binds the `OidcAuth` section and delegates to `AddPortaAuthentication`. Both are fully supported; prefer `AddPortaAuthentication` with the `SessionAuthentication` section for new code, for consistency with the rest of the docs.

### Token refresh resilience - `SessionAuthentication.Resilience`

`Resilience` controls how the BFF retries and circuit-breaks the IdP token endpoint when refreshing access tokens via `ITokenRefreshService` / `IAccessTokenRefreshService`. The defaults are reasonable for most IdPs; tune only if your IdP is rate-limited, slow, or you've measured circuit-breaker false trips.

| Key | Default | Description |
|-----|---------|-------------|
| `EnableRetry` | `true` | Retry transient token-endpoint failures with exponential backoff. Set to `false` to disable retries. |
| `MaxRetryAttempts` | `3` | Max retry attempts. Must be ≥ 1 when `EnableRetry` is `true` (validated at startup). |
| `InitialDelaySeconds` | `1.0` | Base for exponential backoff (`delay = InitialDelaySeconds * 2^attempt`). |
| `UseJitter` | `true` | Add randomization to backoff to spread thundering-herd retries. |
| `EnableCircuitBreaker` | `true` | Open the breaker when the IdP is consistently failing. |
| `CircuitBreakerFailureRatio` | `0.5` | Failure ratio in the sampling window that trips the breaker. |
| `CircuitBreakerSamplingDurationSeconds` | `30.0` | Window over which `CircuitBreakerFailureRatio` is measured. |
| `CircuitBreakerMinimumThroughput` | `10` | Minimum requests in the window before the breaker may trip. |
| `CircuitBreakerBreakDurationSeconds` | `30.0` | How long the breaker stays open before transitioning to half-open. |
| `RequestTimeoutSeconds` | `10.0` | Per-request timeout on calls to the IdP token endpoint. |

### Session key namespace - `SessionAuthentication.SessionKeys`

`SessionKeys.Prefix` (default `"porta"`) is the prefix applied to every session-storage key the BFF writes - access/refresh/id tokens, expiry, API tokens, the auth context, and a `user.*` namespace. When two BFF instances share one Redis/Valkey and use the same prefix, their session writes collide. Set per-instance prefixes (e.g., `"customer-portal.porta"`, `"admin-porta"`) to namespace them.

The per-key suffixes (`AccessTokenKey`, `IdTokenKey`, `RefreshTokenKey`, `ExpiresAtKey`, `ApiAccessTokenKey`, `UserPrefix`, `AuthContextKey`) also have defaults and are rarely worth overriding - change them only if you're migrating from a custom layout.

### Backend service credentials - `BackendService`

`BackendServiceOptions` (section `"BackendService"`) configures the built-in `BasicAuth` and `TokenExchange` backend-auth handlers without requiring you to write a custom `IBackendAuthHandler`.

The `"BackendService"` section is bound automatically by the `AddPortaCore(IConfiguration)` overload. If you wire core options imperatively via `AddPortaCore(Action<PortaCoreOptions>)` instead, bind it yourself: `services.Configure<BackendServiceOptions>(builder.Configuration.GetSection(BackendServiceOptions.SectionName))`.

```json
{
  "BackendService": {
    "BaseUrl": "https://api.internal.example.com",
    "BasicAuth": { "Username": "bff", "Password": "..." },
    "Backends": {
      "PartnerApi": { "Username": "partner-bff", "Password": "..." }
    },
    "DefaultTokenExchangeAudience": "https://api.internal.example.com",
    "TokenExchangeAudiences": {
      "PartnerApi": "https://partner.example.com"
    }
  }
}
```

| Key | Description |
|-----|-------------|
| `BaseUrl` | Optional base URL for backend calls (consumer-facing convenience; not validated at startup). |
| `BasicAuth` | Default Basic credentials used by `BackendAuthPolicies.BasicAuth` when no per-backend entry matches. |
| `Backends` | Per-backend Basic credentials keyed by `BackendRequest.BackendName`. Case-insensitive. |
| `AllowGlobalBasicAuthFallback` | Default `false` (fail closed). When a request names a backend that has no matching `Backends` entry, the BasicAuth handler sends **no** `Authorization` header rather than reusing the global `BasicAuth` default (which could forward credentials meant for a different host). Set `true` for the legacy behaviour where such backends share the global default. Requests with no backend name always use `BasicAuth` regardless of this setting. |
| `DefaultTokenExchangeAudience` | Fallback audience for `BackendAuthPolicies.TokenExchange` when an endpoint doesn't supply one inline via `WithTokenExchange(audience)`. |
| `TokenExchangeAudiences` | Per-backend token-exchange audience override, keyed by `BackendRequest.BackendName`. |

When `BackendAuthPolicies.TokenExchange` is selected without an audience source (inline, default, or per-backend), Porta **fails fast at startup** for any endpoint mapped before the host starts. For cases the startup check can't see statically (e.g. a backend name rewritten at request time via `ModifyRequest`), the runtime backstop surfaces it as a server-side **configuration error (500-class)** - a missing audience is operator misconfiguration, not a user `401` credential rejection.

**What it registers:**
- ASP.NET Core `AddCookie()` + `AddOpenIdConnect()` - framework owns state/nonce/PKCE/code-exchange/id_token validation.
- `DistributedCacheTicketStore` as the cookie scheme's `SessionStore` - tokens live server-side, encrypted via `IDataProtector`. Cookie carries only an opaque ticket id.
- `AddDistributedMemoryCache()` as a fallback (a registered Redis/Valkey cache wins, whether registered before or after `AddPortaAuthentication`).
- `AddDataProtection()` with the configured application name and key lifetime.
- `IAccessTokenRefreshService` - auto-refreshes near-expiry access tokens on each request, with per-user locking.
- Token services: `ITokenRefreshService`, `ITokenRevocationService`, `ITokenExchangeService`, `IApiTokenService`.
- `ISessionManagementService` for admin force-logout and back-channel logout flows.
- `OnTokenValidated` event handler that registers the session metadata + encrypted refresh token after successful sign-in.

### Registration Order

The recommended registration order is:

```csharp
// 1. Core services (always required)
builder.Services.AddPortaCore(options => { ... });

// 2. OIDC auth (if needed)
builder.Services.AddPortaAuthentication(builder.Configuration);

// 3. Custom auth handlers (if needed)
builder.Services.AddPortaAuthHandler<MyCustomHandler>();

// 4. Custom auth provider (if not using OIDC)
builder.Services.AddPortaAuthProvider<ApiKeyAuthProvider>();
```

## Production Configuration

Key settings that should be configured before a production deployment. The library only enforces a subset of these at startup (see [Startup Validation](#startup-validation) below); the rest are caller responsibilities surfaced here so they aren't missed.

| Setting | Environment Variable | Enforced? | Description |
|---------|---------------------|-----------|-------------|
| `SessionAuthentication:Authority` / `ClientId` / `ClientSecret` | `SessionAuthentication__Authority`, etc. | **Yes** - `IValidateOptions<SessionAuthenticationConfiguration>` with `ValidateOnStart`. | Required to start the app when `AddPortaAuthentication` is called. `Authority` must be an absolute http(s) URL. |
| `SessionAuthentication:RequireHttpsMetadata` | - | **Yes** outside Development - `CookieSecurityStartupCheck` throws (event `Porta/14703`) when set to `false`; warns (`Porta/14702`) in Development. Default `true`. | Leave `true` in production. Disabling allows the OIDC handler to fetch metadata over plain HTTP, opening a man-in-the-middle window. |
| `SessionAuthentication:Cookie:SecurePolicy` | - | **Yes** outside Development - `CookieSecurityStartupCheck` throws (event `Porta/14701`) when not `Always`; warns (`Porta/14700`) in Development. Default `Always`. | Keep `Always` in production (see [Cookie Security](#cookie-security)). Other values can emit the auth cookie without the `Secure` attribute. |
| `SessionAuthentication:Challenge:Mode` | - | Value validated at startup. | `Auto` (default) redirects safe document navigations and returns 401 for programmatic requests. `Interactive` restores legacy always-redirect behavior; `Unauthorized` always returns 401. |
| `PortaCore:TrustedHosts` (when any endpoint uses `.WithUserToken()`) | `PortaCore__TrustedHosts__0`, etc. | **Yes** - startup throws if a `WithUserToken()` backend host is not in the list. | See [Trusted Hosts](authentication.md#trusted-hosts). |
| `AllowedRedirectHosts` on `UseOidcLogin` / `UseOidcLogout` | - (configured in code, not via a config section) | Enforced at request time, not startup. | Set via `services.Configure<OidcLoginOptions>(...)` / `Configure<OidcLogoutOptions>(...)` or the per-call lambda on `UseOidcLogin` / `UseOidcLogout` (the lambda wins on conflicts). When empty, only same-origin redirects are accepted; loopback is only accepted when `AllowLocalhost = true` (default `false`). External hosts are rejected with HTTP 400. There is no top-level `Logout:AllowedRedirectHosts` config section. |
| `ConnectionStrings:dataprotection-db` | `ConnectionStrings__dataprotection-db` | Indirect - `AddPortaDataProtectionWithEntityFrameworkStore` resolves the connection string and fails at startup when missing. | PostgreSQL connection for Data Protection keys. Required for HA - see [HA Deployment](ha-deployment.md). |
| HA prerequisites (shared `IDistributedCache`, persistent DP keys) | - | Mixed - a shared `IDistributedCache` (`Porta/14500`) and persistent DP keys (`Porta/14501`) being missing are **warnings only**. But unencrypted DP keys, a hollow key-encryption attestation, and an explicit in-process refresh lock alongside a distributed cache **throw outside Development** (events `Porta/14503`, `Porta/14507`, `Porta/14505`); they warn (`Porta/14502`, `Porta/14506`, `Porta/14504`) in Development. | See [HA Deployment](ha-deployment.md). |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `OTEL_EXPORTER_OTLP_ENDPOINT` | No - read by the OTel SDK. | OpenTelemetry collector endpoint. When set, metrics and traces are exported automatically. |
| `SessionAuthentication:SessionKeys:Prefix` | - | No. | Session key prefix for Redis. Default: `porta`. Change when sharing Redis with other BFF instances. |

### Multi-Replica / HA

Running more than one replica behind a load balancer requires a shared `IDistributedCache` (Redis/Valkey) and shared Data Protection key persistence. The defaults are dev-friendly; the auth pipeline emits a startup warning (event ids `14500`/`14501`) when an HA prerequisite is missing. Sticky sessions are **not** required.

See [HA Deployment](ha-deployment.md) for the full setup.

### Session timeouts - `SessionTimeoutInMin` vs `Cookie.ExpireTimeSpanMinutes`

The two settings look interchangeable but drive different clocks. Get them
both right or one expires while the other thinks the session is still alive.

| Setting | What it controls | Clock |
|---|---|---|
| `SessionAuthentication.SessionTimeoutInMin` | Server-side: ASP.NET Core `IdleTimeout` for `Session` middleware, and a **floor** for the sliding TTL of the session metadata and sub/email revocation indexes (see below). The cookie *ticket* itself is not bound to this value - it lives until the cookie's stamped expiry. | Server wall-clock from last activity. |
| `SessionAuthentication.Cookie.ExpireTimeSpanMinutes` | Client-side **and** server-side: lifetime stamped into the cookie's `expires_at` token (the cookie auth handler refuses principals whose stamp has passed), and the absolute expiry of the server-side cookie ticket entry. | Stamped at sign-in, re-stamped on sliding renewal; checked on every request. |

Recommendation: set both to the **same value**. If you want sessions to extend
on activity, also set `SlidingExpiration = true` (default is `false`); the
server-side ticket and the cookie stamp both slide.

If you set only one:

- `SessionTimeoutInMin` shorter than the cookie lifetime → harmless for
  revocation (the index TTL is the larger of the two values), but ASP.NET Core
  `Session` state can idle out mid-session.
- Cookie lifetime shorter than `SessionTimeoutInMin` → the cookie and its
  server-side ticket expire on the cookie clock; metadata/index entries linger
  until their TTL passes and are pruned on the next admin lookup (wasted cache
  space, no functional impact).

The session metadata and the subject/email revocation indexes - what makes
back-channel logout by `sub` and admin terminate-by-email find live sessions -
slide on `max(SessionTimeoutInMin, Cookie.ExpireTimeSpanMinutes)` and are
re-slid on every cookie ticket write (sign-in and each sliding renewal), so
they cannot expire while the session is still alive. The one way to break that
invariant is post-configuring `CookieAuthenticationOptions.ExpireTimeSpan`
directly past that window; the startup check then logs warning `Porta/14704` -
raise `SessionTimeoutInMin` to match.

### Cookie Security

`SessionAuthentication:Cookie:SecurePolicy` accepts `Always` (default), `SameAsRequest`, or `None`. `SameSite` accepts `Strict` (default), `Lax`, or `None`. Unknown values throw at startup - a typo like `"Allways"` used to silently fall back to a weaker policy; it now fails fast so the misconfiguration surfaces in CI/boot rather than after deploy.

For local development against HTTP, set `SecurePolicy` to `SameAsRequest` explicitly. Don't leave the default `Always` and run on HTTP - the auth cookie will be dropped by the browser.

### Startup Validation

The library validates a focused set of configuration values at startup and fails fast if any is wrong. Anything not in this list (e.g., `AllowedHosts`, a top-level `Logout` section, `BackendService:BaseUrl`) is **not** enforced by the BFF - treat those as host-app concerns.

When `AddPortaAuthentication` is called, `SessionAuthenticationConfigurationValidator` (registered with `ValidateOnStart`) rejects startup if:
- `SessionAuthentication.Authority` is missing or is not an absolute `http`/`https` URL
- `SessionAuthentication.ClientId` is missing
- `SessionAuthentication.ClientSecret` is missing
- `SessionAuthentication.SessionTimeoutInMin` is not positive
- `SessionAuthentication.Cookie.ExpireTimeSpanMinutes` is not positive
- `SessionAuthentication.Cookie.SecurePolicy` or `Cookie.SameSite` is not one of the recognized values (see [Cookie Security](#cookie-security))
- `SessionAuthentication.Challenge.Mode` is not a defined `ChallengeDispatchMode` value
- `SessionAuthentication.Challenge.LoginPath` is set but is not a local absolute path beginning with a single `/`
- `SessionAuthentication.DataProtection.KeyLifetimeDays` is below 7 (ASP.NET Core Data Protection requires a new-key lifetime of at least one week)

When `AddPortaCore` is called, `PortaCoreOptionsValidator` (registered with `ValidateOnStart`) rejects startup if:
- `PortaCore.DefaultTimeout` is not positive
- `PortaCore.TokenRefreshSkew` is negative
- `PortaCore.MaxBodyLogLength` is below `-1` (`-1` = unlimited, `0` = no body logs)
- `PortaCore.IdpErrorBodyMaxBytes` is negative or above 1 MiB

`PortaCore.MaxRetryAttempts` below 1 is *not* an error - it is the documented way to disable retries app-wide. Likewise, non-positive `MaxBackendResponseBytes` / `MaxRawForwardResponseBytes` / `RawForwardReadIdleTimeout` values disable the respective cap.

When `AddReferenceTokenAuthentication` is called, `ReferenceTokenAuthOptionsValidator` (registered with `ValidateOnStart`) rejects startup if:
- `Authority` is missing or is not an absolute `http`/`https` URL
- `TokenHeaderName` is empty
- exactly one of `ClientId` / `ClientSecret` is set (introspection credentials are only sent when both are configured)
- `DefaultCacheDuration` is not positive, or `MaxCacheDuration` is below `DefaultCacheDuration`
- `ValidateAudience` is `true` but both `ValidAudiences` and `ValidClientIds` are empty (every token would be rejected at request time)

Reference-token options are re-read on appsettings reload; startup validation covers the initial values only.

Additional startup failures from other parts of the wiring:
- A transformer endpoint using `WithUserToken()` references a host outside `PortaCore.TrustedHosts` (thrown during endpoint mapping; see [Trusted Hosts](authentication.md#trusted-hosts)).
- `UseOidcBackChannelLogout` is called with `ValidateSignature`, `ValidateIssuer`, or `ValidateAudience` set to `false` outside the Development environment (throws `OptionsValidationException`).
- `UseOidcLogout(options.PerformGlobalLogout = true)` is called against an OIDC handler configured with `SaveTokens = false` - `id_token_hint` cannot be attached to the end-session request.
- `UseSessionAdmin` is called without a `RequirePolicy`, or the named policy is not registered.
- `AddPortaDataProtectionWithEntityFrameworkStore` cannot resolve its connection string.
- Outside Development, `CookieSecurityStartupCheck` throws when `SessionAuthentication.RequireHttpsMetadata` is `false` (event `Porta/14703`) or `Cookie.SecurePolicy` is not `Always` (event `Porta/14701`). Both warn instead of throwing in Development. It also warns (event `Porta/14704`, all environments) when the effective cookie `ExpireTimeSpan` has been post-configured beyond the session revocation-index TTL - see [Session timeouts](#session-timeouts---sessiontimeoutinmin-vs-cookieexpiretimespanminutes).
- Outside Development, `HaConfigurationStartupCheck` throws when Data Protection key persistence is configured but keys are unencrypted at rest with no acknowledgement (event `Porta/14503`), a `protectKeys` action was supplied that registered no `IXmlEncryptor` (event `Porta/14507`), or an in-process refresh lock was registered explicitly while a distributed cache is present (event `Porta/14505`). All three warn instead of throwing in Development. Acknowledge the unencrypted-keys / in-process-lock cases with `AcknowledgeUnencryptedDataProtectionKeys(...)` / `AcknowledgeInProcessRefreshLock(...)`. See [HA Deployment](ha-deployment.md).

### Logging

The library logs through `Microsoft.Extensions.Logging` under the `b17s.Porta.*` namespace. Configure log levels per category as you would for any ASP.NET Core app:

```json
{
  "Logging": {
    "LogLevel": {
      "b17s.Porta": "Information"
    }
  }
}
```

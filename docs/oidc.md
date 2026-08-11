# OIDC Endpoints

The library wires `Microsoft.AspNetCore.Authentication.OpenIdConnect` (the framework's OIDC handler) into a BFF-shaped pipeline: server-side ticket storage, automatic refresh, RFC 7009 token revocation, and back-channel logout. State, nonce, PKCE generation, the auth-code-for-token exchange, and id_token validation are all delegated to the framework - the BFF only adds value where the framework leaves a gap.

## The pipeline at a glance

```
GET /bff/login   →  ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme)
                    ├─ framework builds authorize URL with state/nonce/PKCE
                    └─ 302 to IdP

GET /signin-oidc →  framework handler:
                    ├─ verifies state + nonce + PKCE
                    ├─ exchanges code for tokens at the IdP
                    ├─ validates id_token (signature, iss, aud, exp, nonce)
                    ├─ raises OnTokenValidated
                    │   └─ b17s.Porta: registers session + stores encrypted refresh token
                    └─ SignInAsync(Cookie scheme)
                        └─ DistributedCacheTicketStore: tokens persisted server-side
                            cookie carries only an opaque ticket id

POST /bff/logout →  SignOutAsync(Cookie + OIDC schemes)
                    ├─ b17s.Porta: revokes refresh token at IdP (RFC 7009)
                    └─ framework redirects to IdP end-session endpoint
                    (POST required - a GET would be CSRF-able if the cookie
                     is relaxed to SameSite=Lax)
```

## SPAs and expired sessions

Porta's default challenge scheme dispatches according to the request shape. A safe
`GET` or `HEAD` top-level document navigation (`Sec-Fetch-Mode: navigate` and
`Sec-Fetch-Dest: document`) redirects to OIDC. Fetches, iframe navigations, unsafe
methods, and other programmatic requests receive:

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/problem+json
Cache-Control: no-store
Vary: Sec-Fetch-Mode, Sec-Fetch-Dest, Accept

{"type":"urn:porta:session-expired","title":"Authentication required","status":401,"login":"/bff/login"}
```

For older clients without Fetch Metadata headers, a safe request redirects only when
its parsed `Accept` header explicitly accepts `text/html` or `text/*`; `*/*` alone is
not treated as an interactive navigation. Fetch Metadata is browser-controlled—page
JavaScript cannot set it, although non-browser clients can forge it. Classification
only changes redirect versus 401 and never grants access.

The response intentionally contains a bare login URL. Porta does not anonymously mint
a signed return URL from `Referer`, because doing so would allow an attacker to obtain
transferable tokens for attacker-selected internal destinations. An SPA that wants to
restore the exact page (including its fragment) can keep it locally:

```js
if (response.status === 401) {
  const problem = await response.json();
  sessionStorage.setItem("porta:returnUrl", location.href);
  location.assign(problem.login);
}
```

After login reaches `OidcLoginOptions.DefaultRedirectUri`, the SPA can consume that
session-storage value. The `login` value is the path registered via `UseOidcLogin`
(prefixed with the request's `PathBase`); configure
`SessionAuthentication.Challenge.LoginPath` when the application does not use
`UseOidcLogin`, or to disambiguate multiple login endpoints. When neither is available
the value falls back to `/bff/login`.
Set `Challenge.Mode = ChallengeDispatchMode.Interactive` for the pre-dispatch behavior,
or `Unauthorized` to suppress automatic redirects entirely. A custom synchronous
`Challenge.Classifier` replaces Auto's built-in classifier and is therefore
security-sensitive. Explicit calls to `ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme)`
always invoke OIDC directly and never enter the dispatcher. `ForbidAsync` on the
default scheme returns a plain 403 with no redirect.

## Service registration

Single entry point. Pass an `IConfiguration` containing the `SessionAuthentication` section (or your own section name).

```csharp
builder.Services.AddPortaCore();
builder.Services.AddPortaAuthentication(builder.Configuration);
```

`appsettings.json`:
```json
{
  "SessionAuthentication": {
    "Authority": "https://auth.example.com",
    "ClientId": "my-porta",
    "ClientSecret": "...",
    "Scope": "openid profile email",
    "CookieName": "__Porta",
    "UsePkce": true,
    "QueryUserInfoEndpoint": true,
    "SessionTimeoutInMin": 60,
    "Cookie": {
      "SecurePolicy": "Always",
      "SameSite": "Strict",
      "ExpireTimeSpanMinutes": 60,
      "SlidingExpiration": false
    },
    "DataProtection": {
      "ApplicationName": "MyPorta",
      "KeyLifetimeDays": 90
    }
  }
}
```

`AddPortaAuthentication` registers:
- `AddAuthentication().AddCookie().AddOpenIdConnect()` with options bound from configuration.
- `DistributedCacheTicketStore` as the cookie scheme's `SessionStore`.
- `AddDistributedMemoryCache()` as a fallback (real Redis/Valkey wins via `TryAddSingleton`).
- `AddDataProtection()` with `ApplicationName` and `KeyLifetimeDays`.
- `IAccessTokenRefreshService`, `ISessionManagementService`, `ITokenRefreshService`, `ITokenRevocationService`, `ITokenExchangeService`.

For production, layer Redis on top:
```csharp
builder.Services.AddStackExchangeRedisCache(o => o.Configuration = "...");
```

## Endpoint options composition

All four endpoint shims (`UseOidcLogin`, `UseOidcLogout`, `UseOidcBackChannelLogout`, `UseSessionAdmin`) build their options per call from the DI options pipeline: any `services.Configure<TOptions>(...)` / `PostConfigure<TOptions>(...)` composition is applied first, then the per-call lambda runs last and wins on conflicts. Each call gets a fresh options instance, so two endpoints registered with different lambdas never share state.

## UseOidcLogin

Thin shim: validates the post-login destination (open-redirect guard + signed-return-url policy), then triggers the framework's challenge flow.

```csharp
app.UseOidcLogin();

// Custom path and options
app.UseOidcLogin("/auth/login", options =>
{
    options.DefaultRedirectUri = "/dashboard";
    // Bare hostnames match any port; "host:port" pins the port.
    options.AllowedRedirectHosts = ["app.example.com", "staging.example.com:8443"];
});
```

### Specifying a post-login destination

There are two flows for telling `/bff/login` where to land after authentication. Which one is active depends on `OidcLoginOptions.RequireSignedReturnUrl` (default: `true`).

#### Default - signed `return_url` flow (`RequireSignedReturnUrl = true`)

An unauthenticated caller cannot supply a raw `redirect_uri`; it must present a signed token minted by this server. This blocks attacker-crafted login links from pre-setting a target path the victim never chose.

1. From an authenticated session, `POST /bff/login/sign-return-url?redirect_uri=/dashboard` (the auth cookie must be on the request).
2. Response: `{ "return_url": "<opaque-token>", "expires_in": 600 }`. Lifetime is `OidcLoginOptions.ReturnUrlTtl` (default 10 minutes).
3. Client navigates to `/bff/login?return_url=<opaque-token>`.
4. `ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme)` - the framework builds the authorize URL with state/nonce/PKCE and 302s the browser to the IdP.
5. After auth, the IdP redirects to `/signin-oidc` (the framework's default callback path). **You do not need to write a callback handler.**

If an unauthenticated caller hits `/bff/login?redirect_uri=/dashboard` (raw, unsigned) under this default, the request is rejected with HTTP 400:

```json
{ "error": "redirect_uri must be signed", "sign_endpoint": "/bff/login/sign-return-url" }
```

An *already-authenticated* caller (e.g. a step-up reauth flow) may pass `redirect_uri` directly under either mode - they could navigate to that path themselves anyway.

#### Permissive - raw `redirect_uri` flow (`RequireSignedReturnUrl = false`)

For deployments where every login link is server-rendered or originates inside a trusted UI (no anonymous link-injection threat), the signed flow can be disabled:

```csharp
app.UseOidcLogin("/bff/login", options =>
{
    options.RequireSignedReturnUrl = false;
});
```

Then `/bff/login?redirect_uri=/dashboard` works directly. The open-redirect guard (relative-only or `AllowedRedirectHosts`) still applies regardless of mode.

If no destination is supplied at all, `OidcLoginOptions.DefaultRedirectUri` is used.

Scope and PKCE come from `SessionAuthentication` config; there are no `OidcLoginOptions.AdditionalScopes` / `UsePkce` knobs at the endpoint level.

## UseOidcLogout

Thin shim: validates `redirect_uri`, optionally revokes the refresh token at the IdP, then triggers the framework's sign-out flow.

**HTTP method:** the endpoint only accepts `POST` and returns `405 Method Not Allowed` with `Allow: POST` otherwise. This blocks CSRF logout via `<img src="…/bff/logout">` - Porta defaults the auth cookie to `SameSite=Strict`, but if an operator relaxes it to `Lax` the cookie attaches to top-level GETs, and global logout would then revoke the user's refresh token at the IdP as an attacker-triggered side effect.

**Antiforgery:** by default the endpoint also requires a valid ASP.NET antiforgery token on the POST. This is defense-in-depth on top of the method gate: if an operator later flips the auth cookie to `SameSite=None` (cross-site embedded scenarios), a cross-origin POST would attach the cookie and trigger logout + IdP-side revocation as a side effect. The antiforgery token closes that window. See [Antiforgery for browser callers](#antiforgery-for-browser-callers) below.

```csharp
app.UseOidcLogout();

// JSON response mode for SPA
app.UseOidcLogout("/auth/logout", options =>
{
    options.ReturnJson = true;
    options.PerformGlobalLogout = true;          // revoke refresh token at IdP (RFC 7009) + clear local session
                                                 // NOTE: JSON mode does NOT end the IdP SSO session - see
                                                 // "Global logout from a SPA" below
    options.AllowedRedirectHosts = ["app.example.com"];
    options.DefaultRedirectUri = "/";
    options.RequireAntiforgery = true;           // default; browser callers must present a token
});

// Local logout only - no IdP round-trip
app.UseOidcLogout("/auth/logout", options =>
{
    options.PerformGlobalLogout = false;
});

// Non-browser logout caller (CLI, native app with token auth) - opt out
app.UseOidcLogout("/auth/logout", options =>
{
    options.RequireAntiforgery = false;
});
```

### OidcLogoutOptions

| Option | Default | Notes |
| --- | --- | --- |
| `DefaultRedirectUri` | `/` | Used when the request omits `redirect_uri`. Validated at startup against `AllowedRedirectHosts` / `AllowLocalhost`. |
| `AllowedRedirectHosts` | `[]` | Whitelist of accepted hosts for `redirect_uri`. Entries can be bare hostnames or `host:port`. Empty means same-origin only. |
| `AllowLocalhost` | `false` | When `true`, loopback hosts are accepted as redirect targets even when not in `AllowedRedirectHosts`. |
| `ReturnJson` | `false` | When `true`, return a JSON envelope instead of a redirect. Note this also changes what `PerformGlobalLogout` can do — see below. |
| `PerformGlobalLogout` | `true` | Revoke the refresh token at the IdP (RFC 7009). In **redirect mode** (`ReturnJson = false`) it *also* signs out the OIDC scheme, driving the framework to the IdP end-session endpoint and ending the IdP SSO session. In **JSON mode** (`ReturnJson = true`) it revokes the refresh token and clears the local session **only** — it does **not** end the IdP SSO session (a JSON response cannot also emit the end-session redirect). See [Global logout from a SPA](#global-logout-from-a-spa). |
| `RequireAntiforgery` | `true` | Require a valid ASP.NET antiforgery token on the logout POST. Disable only when logout callers are non-browser (CLI, server-to-server, native app). When `true` and `IAntiforgery` is not registered, the endpoint fails closed with HTTP 403. |

### Antiforgery for browser callers

When `RequireAntiforgery = true` (default), the logout POST must include a valid ASP.NET antiforgery token. The middleware uses `Microsoft.AspNetCore.Antiforgery.IAntiforgery`, which by default reads the token from the `RequestVerificationToken` header (or matching form field). A browser SPA should fetch a token via `IAntiforgery.GetAndStoreTokens` on a GET, then attach it to the logout POST:

```javascript
const csrf = document.cookie.split('; ').find(c => c.startsWith('XSRF-TOKEN='))?.split('=')[1];

await fetch('/bff/logout', {
    method: 'POST',
    headers: { 'RequestVerificationToken': decodeURIComponent(csrf) },
});
```

**Global logout** (the default), in **redirect mode** (`ReturnJson = false`):
1. Revoke the refresh token at the IdP via RFC 7009 (cascades to access tokens for spec-compliant IdPs).
2. `SignOutAsync(Cookie)` clears the cookie + ticket store.
3. `SignOutAsync(OIDC)` lets the framework redirect to the IdP's end-session endpoint with `id_token_hint`. This ends the IdP SSO session, so the next login is *not* silently SSO'd.

**Global logout in JSON mode** (`ReturnJson = true`): only steps 1 and 2 run. Step 3 is **skipped** — a JSON response body cannot also carry the `302` redirect the end-session flow needs. The refresh token is dead and the local BFF session is gone, but the **IdP SSO session is still alive**, so the next `/bff/login` may sign the user straight back in without a credential prompt. To end the IdP session too, the SPA must drive it — see [Global logout from a SPA](#global-logout-from-a-spa).

**Local logout**: `SignOutAsync(Cookie)` only; no IdP round-trip.

### Global logout from a SPA

The IdP SSO session is a cookie the IdP set **in the browser**. Ending it is inherently a browser navigation — the browser has to visit the IdP's end-session endpoint so the IdP can clear that cookie. This library does not (and cannot) do that for you from a JSON response. You have two practical options:

**Option A — use redirect mode for logout (recommended).** If you want true global logout, don't use `ReturnJson` for the logout call. Do a full-page navigation to the logout endpoint and let the framework handle the end-session redirect end to end:

```javascript
// Submit a POST form (so antiforgery + SameSite still apply) and let the browser follow the 302 chain
const form = document.createElement('form');
form.method = 'POST';
form.action = '/bff/logout';
// include your antiforgery token as a hidden field or header-bearing fetch+redirect as your setup requires
document.body.appendChild(form);
form.submit();
```

The browser ends up at the IdP end-session endpoint and then back at your `post_logout_redirect_uri`. SSO is fully cleared.

**Option B — JSON logout, then navigate to the IdP yourself.** Keep `ReturnJson = true` for the local teardown (handy when the SPA wants to react to the JSON first), then send the browser to the IdP end-session endpoint:

```javascript
await fetch('/bff/logout', { method: 'POST', headers: { 'RequestVerificationToken': csrf } });
// local session + refresh token are now gone; finish by ending the IdP session:
window.location = 'https://auth.example.com/connect/endsession'
    + '?post_logout_redirect_uri=' + encodeURIComponent('https://app.example.com/');
```

Caveats for Option B: the BFF holds the `id_token` server-side, so the SPA cannot supply `id_token_hint`. Without it, many IdPs still end the session but may show a "do you want to sign out?" confirmation, and the `post_logout_redirect_uri` usually must be pre-registered with the IdP. The end-session path is provider-specific (`/connect/endsession`, `/v2/logout`, `/oidc/logout`, …) — read it from the IdP's discovery document (`end_session_endpoint`). Where the confirmation prompt and `id_token_hint` matter, prefer Option A.

**JSON response format:**
```json
{
    "success": true,
    "logoutType": "global",
    "redirectUrl": "/dashboard",
    "localSessionCleared": true,
    "tokensRevoked": true
}
```

### Redirect URI validation

Both `UseOidcLogin` and `UseOidcLogout` validate any client-supplied `redirect_uri` before storing or following it:

- **Relative URIs** (`/path`) are accepted as same-origin. **Protocol-relative URIs** (`//host/...`) and backslash variants (`/\host/...`) are rejected with HTTP 400 - these resolve to an external origin in browsers.
- **Absolute URIs** must use `https://`, except loopback hosts (`localhost` / `127.0.0.0/8` / `::1`) which may use HTTP. Loopback is **not** accepted unless `AllowLocalhost = true` (default `false`); in docker/sidecar deployments a permissive loopback fallback is exploitable.
- **Same-origin** matches require both host AND port equality. A redirect to `app.example.com:8443` is not same-origin with a request to `app.example.com` (HTTPS default :443).
- Hosts must match the request origin or appear in `AllowedRedirectHosts`. Entries may be a bare hostname (any port matches) or `host:port` to pin a specific port. Hostnames are compared in IDN/punycode form and are case-insensitive - `müller.example` and `xn--mller-kva.example` are treated as equal.

## UseOidcBackChannelLogout

IdP-initiated back-channel logout endpoint (OpenID Connect Back-Channel Logout 1.0). The framework doesn't implement this; we do.

```csharp
app.UseOidcBackChannelLogout();

// Custom path and options
app.UseOidcBackChannelLogout("/auth/backchannel-logout", options =>
{
    options.ClockSkew = TimeSpan.FromMinutes(5);
    options.ValidateSignature = true;
    options.ValidateIssuer = true;
    options.ValidateAudience = true;
    options.MaxRequestBodyBytes = 64 * 1024;       // 64 KB Content-Length cap
    options.MaxLogoutTokenLength = 16 * 1024;     // 16 KB JWT character cap
    options.RequireLogoutTypHeader = true;        // require typ: logout+jwt
    options.MaxReplayCacheTtl = TimeSpan.FromHours(24);
});
```

Flow:
1. User logs out from another app connected to the same IdP.
2. IdP POSTs a signed `logout_token` JWT to this endpoint.
3. Middleware validates the JWT signature against the IdP's JWKS (via the shared `JwtValidationHelper`). If the token's signing key is missing from the cached JWKS — typically after an IdP signing-key rollover — the metadata is re-fetched and validation retried once, so IdP-initiated logouts keep working across key rotations. Forced re-fetches are throttled to one per authority per 30 seconds, since this endpoint is anonymous and the trigger (an unknown `kid`) is attacker-controllable.
4. Validates the `events` claim contains the back-channel logout event type.
5. Extracts `sid` (session ID) or `sub` and calls `ISessionManagementService.TerminateSessionAsync(...)`.

**Register with your IdP:** Configure your IdP to send back-channel logout requests to this endpoint URL.

### OidcBackChannelLogoutOptions

| Option | Default | Description |
|--------|---------|-------------|
| `ClockSkew` | `5 minutes` | Maximum allowed clock skew when validating the JWT's `exp` / `iat`. |
| `ValidateSignature` | `true` | Validate the logout token signature against the IdP's JWKS. Disabling this lets an anonymous caller terminate arbitrary sessions. |
| `ValidateIssuer` | `true` | Validate the `iss` claim against the configured authority. |
| `ValidateAudience` | `true` | Validate the `aud` claim against the configured client. |
| `MaxRequestBodyBytes` | `64 KB` | Maximum allowed `Content-Length`. The endpoint is anonymous, so this caps memory an unauthenticated caller can force the server to buffer; a spec-compliant logout_token is only a few KB. |
| `MaxLogoutTokenLength` | `16 KB` | Maximum allowed length of the `logout_token` string itself, in characters. Bounds JWT-validator work for obviously-oversized tokens. |
| `RequireLogoutTypHeader` | `true` | Require the JWT header to carry `typ: logout+jwt` per OIDC Back-Channel Logout 1.0 §2.4. Primary defense against an attacker presenting a signed `id_token` or `access_token` from the same issuer/audience. Disable only for legacy IdPs that mint logout tokens with `typ: JWT` or no `typ`. |
| `MaxReplayCacheTtl` | `24 hours` | Upper bound on how long a consumed `jti` is kept in the replay cache (TTL is otherwise `(token.ValidTo - UtcNow) + ClockSkew`). Defends against a misconfigured IdP that mints tokens without `exp` from pinning entries indefinitely. |

**Startup fail-fast.** `ValidateSignature`, `ValidateIssuer`, and `ValidateAudience` default to `true` and exist only as a Development debugging affordance. `UseOidcBackChannelLogout` throws `OptionsValidationException` at startup if any of them is `false` and `IHostEnvironment.IsDevelopment()` is `false`.

## Server-side ticket store

By default, ASP.NET Core's cookie auth handler stores tokens in the cookie itself via `AuthenticationProperties`. For a BFF this means cookies grow with the access/refresh/id tokens (typically 3–5 KB+) and tokens travel over the wire on every request.

`AddPortaAuthentication` instead registers a `DistributedCacheTicketStore` as the cookie scheme's `SessionStore`:

- Cookie carries only an opaque ticket id (~32 bytes): the IdP-issued `sid` claim when present, otherwise a generated `Guid.NewGuid("N")`.
- The actual `AuthenticationTicket` (with tokens) is serialized via `TicketSerializer.Default`, encrypted via `IDataProtector` with purpose `"Porta.AuthTickets.v1"`, and written to `IDistributedCache` under `porta:auth_ticket:{id}`.
- The cache entry expires when the cookie ticket expires: its absolute expiration is the ticket's stamped `ExpiresUtc` (driven by `Cookie.ExpireTimeSpanMinutes`, re-stamped on each sliding renewal when `SlidingExpiration` is enabled). `SessionTimeoutInMin` does **not** control the ticket TTL - see [Session timeouts](configuration.md#session-timeouts---sessiontimeoutinmin-vs-cookieexpiretimespanminutes).

**Cache eviction effectively logs the user out** (the cookie's ticket id no longer resolves). Acceptable for a session store. If you need stronger guarantees, use Redis with persistence and capacity headroom.

**Decrypt failures** (e.g., after Data Protection key rotation without persistent key storage) cause the ticket to be treated as missing - the user is silently logged out and must re-authenticate. To survive key rotation across instances, configure persistent key storage (`PersistKeysToStackExchangeRedis`, `PersistKeysToFileSystem`, etc.) on the `IDataProtectionBuilder`.

## Session token revocation

`TerminateSessionAsync(sessionId, revokeTokens: true)` from the admin API (with `?revokeTokens=true`) revokes the refresh token at the IdP via RFC 7009 (cascades to access tokens for spec-compliant IdPs). Back-channel logout terminates the local session with `revokeTokens: false` - the IdP just told us the user signed out, so calling back to revoke would be redundant.

Revocation requires:
- A refresh token was stored on the session metadata at sign-in time. `OnTokenValidated` calls `ISessionManagementService.RegisterSessionAsync(..., encryptedRefreshToken: ...)`. The token is encrypted via `IDataProtector` with purpose `"Porta.SessionTokenRevocation.v1"`.
- `ITokenRevocationService` is registered (`AddPortaAuthentication` does this).
- `IDataProtectionProvider` is registered (`AddPortaAuthentication` does this).

If any of these are missing, termination still succeeds locally (cookie + ticket store) but logs that IdP-side revocation was skipped:
- `Porta/13813`: `ITokenRevocationService is not registered`
- `Porta/13814`: `IDataProtectionProvider is not registered`
- `Porta/13815`: `no encrypted refresh token on metadata`
- `Porta/13816`: `failed to decrypt refresh token (data protection key rotation?)`

`AccessTokenRefreshService` updates the encrypted refresh token after every successful rotation, so revocation always targets the current refresh token (not a stale rotated-out one).

## Session Administration

For administrative session management, use `UseSessionAdmin()`. **Opt-in** and **requires an authorization policy**.

### Basic Usage

```csharp
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
});

app.UseSessionAdmin("/bff/admin/sessions", options =>
{
    options.RequirePolicy = "AdminOnly";  // REQUIRED - startup fails if missing
    options.RequireAntiforgery = true;    // default; cookie callers must present a token on DELETE
});
```

### SessionAdminOptions

| Option | Default | Description |
|--------|---------|-------------|
| `RequirePolicy` | - | **Required.** Name of an `AddAuthorization` policy. Startup fails if missing or if the policy is not registered. |
| `RequireAntiforgery` | `true` | State-changing requests (`DELETE`) require a valid ASP.NET antiforgery token when the authenticated caller is identified via a cookie scheme. Token-auth callers (bearer / reference tokens / API keys) are exempt because their credentials are not auto-attached cross-origin. Disable only when admin clients are non-browser (CLI, server-to-server). |

### REST Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/bff/admin/sessions?email={email}` | List all sessions for a user |
| `DELETE` | `/bff/admin/sessions/{sessionId}` | Terminate a specific session - antiforgery token required for cookie callers when `RequireAntiforgery = true`. |
| `DELETE` | `/bff/admin/sessions?email={email}` | Terminate all sessions for a user - antiforgery token required for cookie callers when `RequireAntiforgery = true`. |

### Antiforgery for cookie callers

When `RequireAntiforgery = true` (default), a cookie-authenticated `DELETE` must include a valid ASP.NET antiforgery token. The middleware uses `Microsoft.AspNetCore.Antiforgery.IAntiforgery`, which by default reads the token from the `RequestVerificationToken` header (or matching form field). A browser admin UI should fetch a token via `IAntiforgery.GetAndStoreTokens` on a GET, then attach it to subsequent DELETEs:

```javascript
const csrf = document.cookie.split('; ').find(c => c.startsWith('XSRF-TOKEN='))?.split('=')[1];

await fetch('/bff/admin/sessions/abc123', {
    method: 'DELETE',
    headers: { 'RequestVerificationToken': decodeURIComponent(csrf) },
    credentials: 'include'
});
```

CSRF failures are counted under the `bff.csrf.validation_failures` metric (see [telemetry.md](telemetry.md)).

### Optional Query Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `revokeTokens` | Also revoke refresh token at IdP (RFC 7009). Pass `true` / `1` / `yes` to opt in; any other value (or omission) is treated as `false`. | `false` |

### Example Responses

**List sessions:**
```json
{
    "email": "user@example.com",
    "sessionCount": 2,
    "sessions": [
        {
            "sessionId": "abc123",
            "userId": "user-456",
            "createdAt": "2024-01-15T10:00:00Z",
            "lastActivity": "2024-01-15T14:30:00Z",
            "expiresAt": "2024-01-15T22:00:00Z",
            "ipAddress": "192.168.1.100",
            "userAgent": "Mozilla/5.0..."
        }
    ]
}
```

**Terminate session:**
```json
{ "success": true, "sessionId": "abc123", "tokensRevoked": true }
```

**Terminate by email:**
```json
{ "success": true, "email": "user@example.com", "terminatedCount": 2, "tokensRevoked": true }
```

### Security Considerations

- **Disabled by default**: Must be explicitly enabled with `UseSessionAdmin()`.
- **Mandatory auth policy**: No default - callers must specify a policy.
- **Startup validation**: Fails if the specified policy doesn't exist.
- **Audit logging**: All operations are logged at Information level.

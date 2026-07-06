# Raw Forwarding

For endpoints that need to forward responses without JSON parsing (binary files, XML, streaming), use raw forwarding.

## When to Use Raw Forwarding

**Use raw forwarding for:**
- File uploads/downloads (binary content)
- Proxying XML APIs without transformation
- Streaming responses (video, large files)
- Performance-critical pass-through endpoints

**Don't use raw forwarding when:**
- You need to transform the response data
- You need to aggregate multiple backends
- You need to validate or enrich the response

## CallRawAsync

For custom raw forwarding logic in a transformer:

```csharp
public class FileDownloadTransformer : TransformerBase<object>
{
    public override async Task<object> TransformAsync(TransformerContext context)
    {
        var fileId = GetRouteValue(context, "id");

        // The configured backend (from ToBackend(...)/ToAny(...)) is exposed on the
        // context under the "BackendRequest" property; override its Url as needed.
        var backendRequest = (BackendRequest)context.Properties["BackendRequest"];
        var request = backendRequest with
        {
            Url = $"{backendRequest.Url}/files/{fileId}"
        };

        using var result = await context.BackendCaller.CallRawAsync(request, context.CancellationToken);

        if (!result.IsSuccess)
        {
            await WriteErrorResponseAsync(context, result.StatusCode, result.Error!);
            return default!;
        }

        // Stream response directly to client
        context.HttpContext.Response.StatusCode = result.StatusCode;
        context.HttpContext.Response.ContentType = result.ContentType ?? "application/octet-stream";

        if (result.ContentLength.HasValue)
            context.HttpContext.Response.ContentLength = result.ContentLength;

        await result.Response!.Content.CopyToAsync(context.HttpContext.Response.Body);
        return default!;
    }
}
```

### With Request Body (File Upload)

```csharp
public class FileUploadTransformer : TransformerBase<object>
{
    public override async Task<object> TransformAsync(TransformerContext context)
    {
        var request = (BackendRequest)context.Properties["BackendRequest"];
        var contentType = context.HttpContext.Request.ContentType ?? "application/octet-stream";

        using var result = await context.BackendCaller.CallRawAsync(
            request,
            context.HttpContext.Request.Body,
            contentType,
            context.CancellationToken);

        // Forward response...
    }
}
```

### RawBackendResult Properties

| Property | Description |
|----------|-------------|
| `IsSuccess` | True if transport succeeded (a response was received); not necessarily 2xx |
| `StatusCode` | HTTP status code from backend |
| `Response` | Raw `HttpResponseMessage` (dispose after use) |
| `ContentType` | Content-Type header from response |
| `ContentLength` | Content-Length header if available |
| `Error` | Error message on failure |
| `ErrorType` | Type of error (Network, Timeout, Auth, etc.) |

## Zero-Code Raw Forwarding with MapRawForward

For simple proxy endpoints without any transformation, use `MapRawForward()` - no transformer class needed:

```csharp
// Zero-code file proxy
app.MapRawForward()
    .FromGet("/api/files/{id}")
    .ToGet("https://files.internal/files/{id}")
    .WithBackendAuth(BackendAuthPolicies.BasicAuth)
    .AllowAnonymous()
    .Build();

// File upload proxy
app.MapRawForward()
    .FromPost("/api/uploads")
    .ToPost("https://uploads.internal/files")
    .WithBackendAuth(BackendAuthPolicies.BearerToken)
    .Build();
```

## Custom Raw Forwarding with Header Manipulation

For raw forwarding with custom header manipulation, extend `RawForwardTransformer`:

```csharp
// Require authentication for this endpoint via the type-level attribute
[RequiresAuthentication]
public class SecureFileTransformer : RawForwardTransformer
{
    // Modify request before sending to backend
    protected override void ModifyRequest(HttpRequestMessage request, TransformerContext context)
    {
        // Add tenant ID from claims
        var tenantId = context.GetClaim("tenant_id");
        if (!string.IsNullOrEmpty(tenantId))
            request.Headers.Add("X-Tenant-Id", tenantId);

        // Add correlation ID
        request.Headers.Add("X-Correlation-Id", Activity.Current?.Id ?? Guid.NewGuid().ToString());
    }

    // Modify response headers before returning to client
    protected override void ModifyResponseHeaders(HttpResponseHeaders headers, TransformerContext context)
    {
        // Strip internal debug headers
        headers.Remove("X-Internal-Debug");
        headers.Remove("X-Backend-Server");

        // Add security headers
        headers.Add("X-Content-Type-Options", "nosniff");
    }
}

// Registration
builder.Services.AddRawForwardTransformer<SecureFileTransformer>();

// Endpoint
app.MapRawForward<SecureFileTransformer>()
    .FromGet("/api/secure-files/{id}")
    .ToGet("https://files.internal/files/{id}")
    .Build();
```

### RawForwardTransformer Hooks

| Method | Description |
|--------|-------------|
| `[RequiresAuthentication]` (class attribute) | Require auth on the endpoint regardless of configuration. Absent the attribute (and any explicit `.RequireAuth()`/`.AllowAnonymous()`), the endpoint follows `PortaCore:RequireAuthorizationByDefault`, which is `true` by default - so raw-forward endpoints require authentication unless you opt out with `.AllowAnonymous()`. Read at endpoint-build time without instantiating the transformer, so it is safe with scoped or `HttpContext`-bound dependencies. |
| `ModifyRequest()` | Add headers, modify URL before sending |
| `ModifyResponseHeaders()` | Strip/add headers before returning |

`ModifyRequest()` may rewrite `request.RequestUri` to redirect the backend call (e.g. routing to a different upstream per tenant). The rewritten URL is what is actually sent. Two safeguards still apply to the final URL: when the endpoint forwards the user's identity (`WithBackendAuth(BearerToken | TokenExchange)`), the rewritten host is re-validated against `PortaCore:TrustedHosts` before the token is attached - a rewrite to an untrusted host fails closed. And if the rewrite changes the destination *host*, sensitive client headers that were allow-listed via `AllowForwardingHeaders(...)` for the original host are re-scoped and stripped if the new host is not allow-listed for them.

## Header Forwarding & Sensitive Header Stripping

To prevent leaking the BFF's session cookie or client credentials to backends, raw forwarding strips the following headers from the outbound request by default:

- `Cookie`, `Set-Cookie`
- `Authorization`
- `Forwarded` (the standard RFC 7239 header)
- `X-Forwarded-*` (any header starting with this prefix)

Standard hop-by-hop headers (`Connection`, `Host`, `Transfer-Encoding`, etc.) are also stripped. The BFF's session cookie should never reach a backend; the backend should only see access tokens issued via `WithBackendAuth(...)`.

**WebSockets are not proxied.** `Upgrade` and `Connection` are hop-by-hop headers and are stripped (correctly, per RFC 9110 §7.6.1), so a WebSocket handshake arriving at a raw-forward endpoint silently degrades to a plain HTTP exchange - the backend never sees the upgrade request, and the client typically receives a `200`/`426` instead of a `101 Switching Protocols`. If you need WebSocket proxying, route those paths through a dedicated reverse proxy (e.g. YARP) instead of a raw-forward endpoint.

The forwarding-metadata headers (`Forwarded`, `X-Forwarded-*`) are stripped because a client can spoof them: a backend (or its forwarded-header middleware) that trusts them would otherwise see an attacker-chosen client IP, host, or scheme. See [Trusting a Front Reverse Proxy](#trusting-a-front-reverse-proxy) below to relay them when the BFF genuinely sits behind one.

`Content-Length` and `Transfer-Encoding` are additionally stripped from the *outbound request* - `StreamContent` will re-assert the correct framing for the body the BFF actually sends. Carrying the inbound values forward would create a request-smuggling primitive (CL.TE / CL.CL) where the BFF and backend disagree on where the request ends. Response-side `Content-Length` is left intact and flows back to the client normally.

Entity (content) headers other than the framing pair above are **preserved** on the forwarded body: `Content-Type`, `Content-Encoding`, `Content-Disposition`, `Content-Language`, `Content-Range`, `Content-Location`, `Content-MD5`, `Allow`, `Expires`, and `Last-Modified` are carried onto the outbound request content rather than dropped, so uploads (e.g. a `gzip`-encoded or ranged body) reach the backend intact.

The request body is forwarded for **any** HTTP method that actually carries one - detected via `Content-Length` or a chunked `Transfer-Encoding`, not an allowlist of verbs - so a `DELETE` or `OPTIONS` with a body (e.g. a bulk-delete payload) is proxied just like `POST`/`PUT`/`PATCH`. A bodyless request (e.g. a plain `GET`) sends no request content.

## Response Size and Idle Timeouts

To bound BFF egress and defeat slow-loris backends, raw-forward responses are subject to two limits configured on `PortaCoreOptions`:

- `MaxRawForwardResponseBytes` (default 100 MiB) - total bytes the BFF will stream from a backend before aborting with `502 Backend response too large`. Set to a non-positive value to disable.
- `RawForwardReadIdleTimeout` (default 30s) - maximum time between successive reads. A backend that pauses longer (drip-feeding bytes to pin a worker) gets `504 Backend response stalled`.

Both limits abort mid-stream if they trip after headers have been written, which intentionally tears the connection rather than presenting the client with a silently truncated body.

> **Long-lived streams (SSE, long polling):** the idle timeout applies to *any* streamed response, so a Server-Sent Events stream that goes quiet for more than 30 seconds is torn down with `504 Backend response stalled`. If you forward SSE through a raw-forward endpoint, either raise `RawForwardReadIdleTimeout` above the longest expected gap between events, or have the backend emit periodic keep-alive comments (`: ping\n\n`) inside the timeout window.

## Backend Error Mapping

Built-in raw-forward endpoints (`MapRawForward` / `AddRawForwardTransformer`) apply the same `IBackendErrorMapper` as the typed transformer routes. By default a **backend** `401`/`403` is mapped to `502 Bad Gateway` *before* the response is relayed: a backend credential failure means the BFF's credentials to the backend are wrong, not that the user's session is invalid, so streaming the raw `401` would wrongly sign the user out on the frontend. When a status is remapped, the backend body is **not** streamed; the client receives a clean `{ "error": "..." }` JSON payload with the mapped status.

Statuses the mapper passes through (e.g. `404`, `409`, `500`) are relayed verbatim — raw forward is a proxy and those are legitimate to surface to the client. Register a custom `IBackendErrorMapper` (or `PassThroughBackendErrorMapper` to relay `401`/`403` unchanged) to override this; see [transformers.md](transformers.md) for the contract.

> This mapping applies to the built-in pipeline. A custom transformer that calls `CallRawAsync` directly (see [CallRawAsync](#callrawasync) above) owns its own status handling — `RawBackendResult.IsSuccess` reflects transport success, not the backend HTTP status.

### Request Direction — Kestrel Reliance

The two limits above guard the **response** direction (backend → BFF → client) only. Porta deliberately does **not** add a per-endpoint cap on the **request** direction (client → BFF → backend); raw-forward streams the incoming request body straight through to the backend. Protection against an over-large or slow-loris **upload** is delegated to Kestrel's global server limits, which you should configure for your deployment:

- `KestrelServerLimits.MaxRequestBodySize` (default 30 MiB) — rejects an over-large upload with `413 Payload Too Large`. Set it to match the largest legitimate raw-forward upload (or `null` to disable, only behind another bound).
- `KestrelServerLimits.MinRequestBodyDataRate` (default 240 bytes/s with a 5s grace) — aborts a client that dribbles the request body to pin a worker (slow-loris upload).
- `KestrelServerLimits.RequestHeadersTimeout` (default 30s) — bounds how long a client may take to send request headers.

```csharp
builder.WebHost.ConfigureKestrel(o =>
{
    o.Limits.MaxRequestBodySize = 50 * 1024 * 1024; // 50 MiB
    o.Limits.MinRequestBodyDataRate = new MinDataRate(bytesPerSecond: 240, gracePeriod: TimeSpan.FromSeconds(5));
});
```

These limits are process-global rather than per-endpoint. If a single raw-forward route needs a different upload ceiling than the rest of the app, scope it with `[RequestSizeLimit(...)]`-style metadata or a dedicated middleware in front of that route. There is no `MaxRawForwardRequestBytes` option; the request-direction posture is intentionally the host's Kestrel configuration, documented here so the asymmetry with the response caps is explicit rather than an oversight.

### Opting Headers Back In

If a specific endpoint needs a sensitive header to pass through (e.g. forwarding a client's `Authorization` to a trusted internal service), use `AllowForwardingHeaders()`:

```csharp
// Forward Authorization header - to ANY destination
app.MapRawForward()
    .FromGet("/api/proxy/{*path}")
    .ToGet("https://internal.example.com/{**path}")
    .AllowForwardingHeaders(["Authorization"])
    .Build();

// Forward Authorization header - only when the destination host is trusted
app.MapRawForward()
    .FromGet("/api/proxy/{*path}")
    .ToGet("https://internal.example.com/{**path}")
    .AllowForwardingHeaders(
        headers: ["Authorization", "X-Tenant-Id"],
        destinationHosts: ["internal.example.com"])
    .Build();
```

> **Subtree proxying:** to forward a whole nested path, use a **catch-all** placeholder
> (`{**path}` or `{*path}`) in *both* the route and the backend template. A catch-all
> backend placeholder preserves the `/` separators in the matched value, so
> `/api/proxy/a/b/c` forwards to `{internalApi}/a/b/c`. A plain single-segment
> placeholder (`{path}`) instead percent-encodes the separators (`a%2Fb%2Fc`) — by
> design, so an `{id}`-style value can never inject extra path segments. `.`/`..`
> traversal segments are rejected in both modes. See
> [Route Parameter Interpolation](endpoints.md#route-parameter-interpolation) for the full
> encoding and validation rules (shared by all endpoint builders).

### Global Defaults

Set a default allow-list for all raw-forward endpoints via `PortaCoreOptions`:

```csharp
builder.Services.AddPortaCore(opts =>
{
    opts.DefaultRawForwardHeaderPassThrough.AllowedHeaders.Add("X-Tenant-Id");
    opts.DefaultRawForwardHeaderPassThrough.AllowedDestinationHosts.Add("internal.example.com");
});
```

A per-endpoint `AllowForwardingHeaders()` call replaces the global defaults for that endpoint.

### Trusting a Front Reverse Proxy

When the BFF itself sits behind a reverse proxy (nginx, an ingress controller, a load balancer), that proxy legitimately sets `Forwarded` / `X-Forwarded-*` describing the *real* client, and backends often need that chain intact. Stripping these headers unconditionally (see above) would break that.

List the proxy's address (or CIDR range) in `TrustedForwardingProxies`. When the **inbound connection's remote IP** matches, the forwarding-metadata headers (`Forwarded` and the `X-Forwarded-*` family) are relayed to the backend instead of being stripped. A request from any other source still has them stripped, so a direct client cannot spoof them:

```csharp
builder.Services.AddPortaCore(opts =>
{
    // Single proxy address, or a CIDR range for a pool of proxies.
    opts.DefaultRawForwardHeaderPassThrough.TrustedForwardingProxies.Add("10.0.0.5");
    opts.DefaultRawForwardHeaderPassThrough.TrustedForwardingProxies.Add("10.0.0.0/8");
});
```

Notes:

- Entries may be single IPs (`10.0.0.5`, `::1`) or CIDR ranges (`10.0.0.0/8`, `fd00::/8`). IPv4-mapped IPv6 peers (`::ffff:10.0.0.5`, the form Kestrel reports on a dual-stack socket) are normalized before matching, so an IPv4 entry still matches.
- This gate covers **only** the forwarding-metadata family. `Cookie`, `Set-Cookie`, and `Authorization` are never unlocked by proxy trust — opt those in explicitly with `AllowForwardingHeaders(...)` / `AllowedHeaders` if a trusted backend truly needs them.
- The remote IP is the *immediate* TCP peer. If multiple proxy hops sit in front of the BFF, trust the hop that actually connects to it.
- **Security:** any host listed here is fully trusted to dictate the forwarded client IP, host, and scheme. Keep the list as narrow as the deployment allows; never list a broad public range.

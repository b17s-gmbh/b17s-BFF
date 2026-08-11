# Telemetry

The BFF framework automatically generates OpenTelemetry traces and metrics for all transformer executions and backend calls. This is enabled by default and requires no additional code in transformer implementations.

## Automatic Instrumentation

When `EnableTelemetry` is true (default), the framework automatically instruments transformer and raw-forward endpoint execution, backend HTTP calls, authentication, token exchange/refresh, session lifecycle, CSRF validation, the session-admin endpoint, and OIDC back-channel logout. Activities are emitted by `PortaActivitySource` (source name `b17s.Porta`) and metrics by `PortaMetrics` on the same meter name. Each activity uses a **fixed category name**; the specific transformer/backend is carried on a **tag**, never baked into the activity name (see the note below).

The whole-pipeline request instrumentation in the last row is **opt-in** - the BFF has no other always-on middleware, so it only runs when you add [`app.UsePortaTelemetry()`](#request-lifecycle-instrumentation-useportatelemetry).

| Component | Activity name | Related metrics |
|-----------|---------------|-----------------|
| Transformer execution | `bff.transformation` (with `bff.transformation.strategy` tag set to the transformer class name) | `bff.transformation.duration` |
| Raw-forward execution | `bff.raw_forward` (with `bff.transformation.strategy` tag set to the transformer class name and `bff.component` = `raw_forward`) | `bff.transformation.duration` (`strategy` = `RawForward:{name}`) |
| Backend HTTP calls | `bff.backend` (with `bff.backend.service` tag set to the service hostname) | `bff.backend.duration`, `bff.backend.requests`, `bff.backend.errors` |
| Aggregator child spans | `bff.backend` (one per parallel backend, `bff.component` = `aggregator`, parented to the transformation activity) | `bff.backend.duration`, `bff.backend.requests`, `bff.backend.errors` (from the inner backend call) |
| Authentication (`IAuthenticationProvider` resolution) | `bff.authentication` (child of the endpoint span) | `bff.auth.duration`, `bff.auth.successes`, `bff.auth.failures` |
| Token exchange | `bff.token_exchange` | - |
| Token refresh (cookie-session + API token) | `bff.token_refresh` | `bff.token.refreshes`, `bff.token.refresh_failures` |
| Session lifecycle | - (recorded inside the OIDC callback / admin / back-channel spans) | `bff.session.created`, `bff.session.invalidated`, `bff.sessions.active` |
| CSRF validation (logout + session-admin) | - | `bff.csrf.validation_failures` |
| Session-admin endpoint | `bff.session_admin` | - |
| OIDC back-channel logout | `bff.backchannel_logout` | - |
| Refresh-lock cleanup timer | - | `bff.session.lock_cleanup_runs`, `bff.session.stale_locks_cleaned` |
| Incoming request lifecycle (opt-in, `UsePortaTelemetry()`) | `bff.request` | `bff.request.duration`, `bff.request.size`, `bff.response.size`, `bff.requests.active` |

> Activity names are **fixed category strings** (`bff.transformation`, `bff.raw_forward`, `bff.backend`, …) - the specific transformer or backend is never baked into the activity name. Each span carries a tag (`bff.transformation.strategy`, `bff.backend.service`) that names it. Don't look for composed names like `bff.transformer.{Name}` or `bff.backend.{ServiceName}` - **search by tag, not by activity name.**

### Request-lifecycle instrumentation (`UsePortaTelemetry()`)

The `bff.request` span and the request/response-size, duration, and in-flight-count metrics cover the **entire** request pipeline, not just Porta endpoints. Because Porta has no always-on middleware, this is opt-in: register it as early as possible so it brackets everything.

```csharp
var app = builder.Build();
app.UsePortaTelemetry();   // first, so it brackets the whole pipeline
app.UseRouting();
// ... auth, endpoints, etc.
```

The matched low-cardinality route **template** (e.g. `/api/users/{id}`) is read back from the resolved endpoint after the inner pipeline runs; requests that match no route are recorded under a single `unmatched` route series. The middleware is a no-op pass-through when `EnableTelemetry` is `false`.

### Session-lifecycle metrics and the active-sessions gauge

`bff.session.created` / `bff.session.invalidated` are counters; `bff.sessions.active` is an up/down gauge incremented on create and decremented on each explicit termination. `bff.session.invalidated` carries a `reason` tag (`logout`, `backchannel`, `admin`, …). To keep the gauge balanced, **cookie logout terminates the server-side session** (in addition to clearing the cookie), and a terminate against an already-gone session never double-decrements. Note the gauge is still a *lower bound* on truly-active sessions: a session evicted purely by distributed-cache expiry (never explicitly terminated) is not counted as an invalidation, so the gauge can drift upward over long-lived deployments.

### Reserved spans (declared but not yet emitted)

Two activity names are defined on `PortaActivitySource` but not yet started by any production path - queries against them return no data, and they are reserved for future use: `bff.session` (session-lifecycle metrics are emitted, but without a dedicated span) and `bff.health_check`.

## Metric reference

All counters and histograms below are emitted under the `b17s.Porta` meter. Source of truth is [`PortaMetrics.cs`](../src/Telemetry/PortaMetrics.cs) - when in doubt, read the meter declarations there. The `bff.request.*`, `bff.response.size`, and `bff.requests.active` instruments require the opt-in [`UsePortaTelemetry()`](#request-lifecycle-instrumentation-useportatelemetry) middleware; everything else is automatic when `EnableTelemetry` is true.

### Counters

| Metric | Tags | Description |
|--------|------|-------------|
| `bff.backend.requests` | `service`, `protocol`, `status_code` | Backend HTTP requests. |
| `bff.backend.errors` | `service`, `protocol`, `status_code` | Backend requests with `status_code >= 400`. |
| `bff.auth.failures` | `reason`, `provider` (optional) | Authentication failures (`reason` = `unauthenticated`, `provider_threw`). |
| `bff.auth.successes` | `provider` (optional) | Successful authentications (`provider` = short provider name, e.g. `SessionAuthProvider`). |
| `bff.auth.challenges` | `outcome` | Default challenge responses (`redirect` or `unauthorized`). |
| `bff.token.refreshes` | `reason` (optional) | Successful token refreshes at the IdP (cookie-session refresh, plus `reason` = `api_token` for API-token refreshes). |
| `bff.token.refresh_failures` | `reason` (optional) | Failed token refreshes (`reason` = `invalid_grant`, `transient`, `api_token`). |
| `bff.csrf.validation_failures` | `reason` | Antiforgery/CSRF validation failures (`reason` = `oidc_logout`, `session_admin`). |
| `bff.session.created` | - | Sessions created (also increments `bff.sessions.active`). |
| `bff.session.invalidated` | `reason` | Sessions invalidated (`reason` = `logout`, `backchannel`, `admin`, …; also decrements `bff.sessions.active`). |
| `bff.session.lock_cleanup_runs` | - | Stale-lock cleanup timer executions. |
| `bff.session.stale_locks_cleaned` | - | Stale per-user refresh locks reclaimed. |

### Histograms

| Metric | Unit | Tags | Description |
|--------|------|------|-------------|
| `bff.request.duration` | `ms` | `method`, `route`, `status_code` | End-to-end request processing time. Nonstandard HTTP methods collapse to `_OTHER` (OTel `http.request.method` convention); unrouted requests collapse to `route` = `unmatched`. Requires `UsePortaTelemetry()`. |
| `bff.backend.duration` | `ms` | `service`, `protocol` | Backend call duration. |
| `bff.transformation.duration` | `ms` | `strategy` | Time spent inside the transformer's `TransformAsync` (raw-forward records `strategy` = `RawForward:{name}`). |
| `bff.auth.duration` | `ms` | `provider` | Time spent in `IAuthenticationProvider` resolution. |
| `bff.request.size` | `bytes` | `method` | Incoming request body size (from `Content-Length`). Nonstandard HTTP methods collapse to `_OTHER`. Requires `UsePortaTelemetry()`. |
| `bff.response.size` | `bytes` | `status_code` | Outgoing response body size. Requires `UsePortaTelemetry()`. |

Latency histograms use the OpenTelemetry `http.server.request.duration`-style buckets (`0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000` ms). Size histograms cover `256 B → 256 MiB` so the `MaxBackendResponseBytes` (10 MiB) and `MaxRawForwardResponseBytes` (100 MiB) caps land in real buckets.

### UpDownCounters

| Metric | Description |
|--------|-------------|
| `bff.sessions.active` | Active sessions. Incremented on `bff.session.created`, decremented on `bff.session.invalidated`. See the [gauge note](#session-lifecycle-metrics-and-the-active-sessions-gauge) on expiry drift. |
| `bff.requests.active` | In-flight requests. Requires `UsePortaTelemetry()`. |

## Span Hierarchy

Activity names are the fixed category strings (`bff.transformation`, `bff.backend`); the specific transformer/backend is carried on a tag, not baked into the name (see the note under [Automatic Instrumentation](#automatic-instrumentation)). Porta's top-level endpoint span (`bff.transformation` here) is parented directly under the host's ambient ASP.NET Core request activity. The tags are shown in brackets below:

```
Incoming HTTP Request
└── ASP.NET Core Activity (auto)
    └── bff.transformation                [bff.transformation.strategy = EnrichedUserProfileTransformer]
        ├── bff.backend                   [bff.backend.service = api.internal.com]
        │   └── HTTP GET api.internal.com (auto)
        └── bff.backend                   [bff.backend.service = products.internal.com]
            └── HTTP GET products.internal.com (auto)
```

## Trace Context Propagation

W3C Trace Context headers (`traceparent`, `tracestate`) are automatically propagated to all backend HTTP calls via `AddHttpClientInstrumentation()`. This enables end-to-end distributed tracing across services.

## Configuration

```csharp
builder.Services.AddPortaCore(options =>
{
    // Disable telemetry if needed (default: true)
    options.EnableTelemetry = false;
});
```

## Tags and Attributes

Activity tags emitted by `PortaActivitySource`. Source of truth is [`PortaActivitySource.cs`](../src/Telemetry/PortaActivitySource.cs).

### General

- `bff.service.name`
- `bff.component` - `"transformer"`, `"aggregator"`, `"backend"`, etc.

### HTTP

- `http.method`, `http.url`, `http.status_code`, `http.route`

### Backend

- `bff.backend.service` - service hostname
- `bff.backend.protocol` - `"http"`
- `bff.backend.endpoint`, `bff.backend.operation`

### Transformation

- `bff.transformation.strategy` - transformer class name
- `bff.transformation.rule`

### Authentication

- `bff.auth.provider` - `"SessionAuthProvider"`, `"JwtBearerAuthProvider"`, `"ReferenceTokenAuthProvider"`, etc.
- `bff.auth.user_id`
- `bff.auth.token_type`

### Session

- `bff.session.id`
- `bff.session.user_id`

### Health check

- `bff.health.status`, `bff.health.backend_count`

### Errors

- `error.type`, `error.message`

Stack traces are intentionally **not** exposed as a tag (high cardinality + inner-exception messages frequently contain PII). Use `Activity.AddException(ex)` instead, which records the stack trace as event-scoped attributes per OpenTelemetry semantic conventions.

## Exporting Traces

Traces are exported when `OTEL_EXPORTER_OTLP_ENDPOINT` is configured. The activity source is registered with OpenTelemetry in ServiceDefaults.

### Example: Jaeger

```bash
# Start Jaeger
docker run -d --name jaeger \
  -p 16686:16686 \
  -p 4317:4317 \
  jaegertracing/all-in-one:latest

# Configure app
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
```

### Example: Aspire Dashboard

When running with .NET Aspire, traces are automatically exported to the Aspire dashboard.

## Backend Call Logging

`BackendCaller` separates structured *metadata* logs from *body* logs so that production log sinks do not capture sensitive payloads (access tokens, refresh tokens, PII) by default.

| Event ID | Level | What it logs |
|----------|-------|--------------|
| 14005 `BackendErrorResponseMeta` | Warning | URL, status, reason, body size, content-type |
| 14006 `BackendDeserializationFailed` | Error | URL, status, body size, exception |
| 14007 `BackendResponseMeta` | Debug | URL, status, body size, content-type |
| 14015 `BackendErrorResponseBody` | **Trace** | Error response body, capped by `PortaCore:MaxBodyLogLength` |
| 14016 `BackendDeserializationFailedBody` | **Trace** | Body that failed to deserialize, capped by `PortaCore:MaxBodyLogLength` |
| 14017 `BackendResponseBody` | **Trace** | Response body, capped by `PortaCore:MaxBodyLogLength` |

Body logs are emitted at `LogLevel.Trace`, which is disabled by default in production. Enable Trace only for the `b17s.Porta.Transformers.BackendCaller` category in development or with operator approval - never enable it globally on a system that brokers tokens or PII.

### Body length cap (`PortaCore:MaxBodyLogLength`)

To bound the blast radius of accidentally enabling Trace logs, body events 14015/14016/14017 are truncated to the first `MaxBodyLogLength` characters (default `512`). Truncated entries get a `… (truncated, N chars total)` suffix so you can still see the full size in the meta log (14005/14006/14007).

| Value | Behavior |
|-------|----------|
| `> 0` | Truncate body to N characters (default `512`) |
| `0` | Do not emit body events at all - only metadata logs are written |
| `-1` | Unlimited; full body is logged |

GraphQL responses and any payload that may include access tokens, refresh tokens, or PII (e.g. `me { ... }` queries, OIDC userinfo) should keep the default cap. Set `-1` only in isolated development environments where you have already accepted the risk.

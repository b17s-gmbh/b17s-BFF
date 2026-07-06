# Health Checks

`AddPortaHealthChecks()` registers opt-in health checks for the dependencies only Porta can
check correctly: the IdP (authority auto-resolved from Porta's auth options), the distributed
cache backing sessions/locks/revocation, and the Data Protection key ring + key store. It uses
the standard `Microsoft.Extensions.Diagnostics.HealthChecks` framework from the shared
framework - no extra packages.

**Registration only.** The library never calls `MapHealthChecks()` and adds no middleware:
you decide whether and where to expose health endpoints. Every check auto-skips (reports
Healthy with a "skipped" description) when its dependency isn't configured, so the one-liner
is safe in every deployment shape.

## Quick start

```csharp
builder.Services.AddPortaHealthChecks();

var app = builder.Build();

app.MapHealthChecks("/healthz/ready", new HealthCheckOptions
{
    // Filter on "ready" so any other ready-tagged checks the host registers are included too.
    // Use "porta" instead to scope the endpoint to Porta's checks only.
    Predicate = r => r.Tags.Contains("ready"),
});
app.MapHealthChecks("/healthz/live", new HealthCheckOptions
{
    Predicate = _ => false,   // liveness = process is up; no dependency checks (see below)
});
```

`AddPortaHealthChecks` returns the `IHealthChecksBuilder`, so you can chain your own checks.
Call it once; a second call throws.

## The checks

| Name | What it probes | Default failure status |
|------|----------------|------------------------|
| `porta:idp-discovery` | `{authority}/.well-known/openid-configuration` for every distinct authority on `SessionAuthenticationConfiguration` and `ReferenceTokenAuthOptions`, over the network | `Degraded` |
| `porta:store:distributed-cache` | Set/get/remove round-trip on the registered `IDistributedCache` (sessions, refresh locks, revocation, HybridCache L2) | `Unhealthy` |
| `porta:store:data-protection` | `Protect`/`Unprotect` round-trip on the key ring; plus `CanConnect` on the key database when Porta's EF key store is registered | `Degraded` |

All checks are tagged `["porta", "ready"]`.

Why the IdP probe goes over the network instead of asking `IDiscoveryService`: the discovery
document is cached by `ConfigurationManager`, so the cached copy stays green throughout an IdP
outage. The probe requires a direct 2xx; redirects fail the check (and name the redirect
target) because a redirecting authority breaks the OIDC handshake even when the target answers
200.

## Configuration

Defaults need no options. To override:

```csharp
builder.Services.AddPortaHealthChecks(o =>
{
    o.ProbeTimeout = TimeSpan.FromSeconds(2);        // per-check probe budget (default 5s)
    o.IdpProbeUrl = "https://idp.internal/health";   // probe this instead of {authority}/.well-known/...
    o.IdpProbeMethod = "HEAD";                       // GET (default) or HEAD
    o.CheckDistributedCache = false;                 // never register this check
    o.CheckDataProtection = true;                    // missing dependency = failure, not skip
    o.IdpFailureStatus = HealthStatus.Unhealthy;     // override a failure status
});
```

Each `Check*` switch is tri-state:

- `null` (default) - **auto**: probe iff the dependency is configured/resolvable at execution
  time, otherwise report Healthy with a "skipped" description.
- `true` - **required**: a missing dependency is reported with the check's failure status.
- `false` - the check is not registered at all.

Probes carry no credentials, follow no redirects, and record only status code, duration, and
host+path - never query strings or response bodies.

## Readiness vs. liveness (Kubernetes)

Wire the Porta checks into **readiness only** and keep liveness dependency-free:

```yaml
readinessProbe:
  httpGet: { path: /healthz/ready, port: 8080 }
  periodSeconds: 10
livenessProbe:
  httpGet: { path: /healthz/live, port: 8080 }
  periodSeconds: 10
```

A readiness failure only removes the pod from rotation - reversible, and the correct response
to a dependency outage. A liveness failure **restarts the container**, and restarting never
fixes an unreachable cache, database, or IdP - it causes restart loops for the whole outage
instead. That's why the quick start maps `/healthz/live` with `Predicate = _ => false`: it
returns 200 as long as the process serves requests, nothing more.

### Degraded vs. Unhealthy

- The distributed-cache check defaults to `Unhealthy`: a dead session store fails every
  authenticated route, so the pod should leave rotation.
- The IdP and Data Protection checks default to `Degraded`: an unreachable IdP blocks new
  sign-ins but existing sessions keep working, and the cached key ring keeps traffic flowing -
  pulling pods from rotation wouldn't help either case.

Note ASP.NET Core's default response mapping returns **200 for `Degraded`** (only `Unhealthy`
maps to 503), so a Degraded pod stays in rotation by default - that is intentional here. The
overall JSON status still says `Degraded` for dashboards and alerting.

## Notes and caveats

- **Security**: expose only the status. The default `MapHealthChecks` response is the bare
  status string; if you add a detailed response writer (per-check data), keep that endpoint
  off the public edge - descriptions name hosts and implementation types.
- **In-memory cache**: when the resolved `IDistributedCache` is the in-memory
  `MemoryDistributedCache`, the check reports Healthy without probing (an in-process
  dictionary can't fail) and logs a one-time warning - sessions are then NOT shared across
  instances. See [HA Deployment](ha-deployment.md).
- **Not live secret-store monitoring**: the Data Protection round-trip exercises the cached
  key ring. A Key Vault / certificate outage surfaces at key rotation, not on the next scrape.
  Use your vault vendor's monitoring for that.
- **Backend URL probes are out of scope**: for plain "is this URL up" checks on your backends,
  use the community package `AspNetCore.HealthChecks.Uris` (`AddUrlGroup`) alongside these
  checks - `AddPortaHealthChecks` returns the builder so they chain naturally.

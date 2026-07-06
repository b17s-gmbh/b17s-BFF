# High Availability Deployment

How to run b17s.Porta behind a load balancer with multiple replicas, **without sticky sessions**.

## What "HA" means here

- N replicas behind a load balancer.
- Any request can land on any replica (round-robin, least-connections, ...).
- Rolling deploys: old and new replicas serve simultaneously during a deploy.
- Sign-in (OIDC redirect → callback) must work even when the callback lands on a different replica than the one that issued the redirect.

The library is designed to be HA-safe under those constraints, but **you must wire three things**. The defaults are dev-friendly, not HA-ready, and the auth pipeline emits a startup warning when an HA prerequisite is missing.

## The three things you must share across replicas

### 1. `IDistributedCache` - Redis or Valkey

The auth ticket store, session store, session-metadata index, and admin lookups all live in `IDistributedCache`. Without a real distributed cache, every replica falls back to its own in-memory cache and sessions become per-instance.

Register Redis before or after `AddPortaAuthentication` - the order doesn't matter. A real registration always wins over the in-memory fallback, and the refresh-lock auto-pick and HA startup check both inspect the *effective* cache from the built container:

```csharp
builder.Services.AddStackExchangeRedisCache(opts =>
{
    opts.Configuration = builder.Configuration["Redis:ConnectionString"];
});

builder.Services.AddPortaAuthentication(builder.Configuration);
```

Or via .NET Aspire:

```csharp
builder.AddRedisDistributedCache("cache");
builder.Services.AddPortaAuthentication(builder.Configuration);
```

If no `IDistributedCache` is registered, the library logs a warning at startup (event id `14500`).

### 2. Data Protection key ring - shared persistence **and** encryption at rest

ASP.NET Data Protection encrypts auth tickets, the OIDC correlation/nonce cookie, and the encrypted refresh tokens stored on session metadata. Without **shared key persistence**, every replica generates its own keys at startup. A cookie minted on replica A then fails to decrypt on replica B and the user gets thrown back to sign-in (or, during the OIDC redirect, the callback fails because the correlation cookie is unreadable).

Persisted keys must also be **encrypted at rest**. The keys themselves are credential-equivalent - anyone who can read the storage row (DB row, Redis hash, blob) can decrypt every active session, every refresh token, and forge new tickets. The library refuses to start in non-Development environments if persistence is configured without a key encryptor (or an explicit acknowledgement, see below).

The library does not pick a backend automatically because it doesn't know which database or cache you run. Pick **one** persistence backend and **one** key encryptor:

**Option A - relational database (recommended if you already run one).** Uses the bundled `DataProtectionDbContext`:

```csharp
using var cert = new X509Certificate2(
    builder.Configuration["DataProtection:CertPath"]!,
    builder.Configuration["DataProtection:CertPassword"]);

builder.Services.AddPortaDataProtectionWithEntityFrameworkStore(
    opts => opts.UseNpgsql(builder.Configuration.GetConnectionString("dataprotection-db")),
    dp => dp.ProtectKeysWithCertificate(cert));

builder.Services.AddPortaAuthentication(builder.Configuration);
```

Run the EF migration once (the table is `DataProtectionKeys` by default) - any standard `dotnet ef database update` flow against `DataProtectionDbContext` will create it.

To avoid colliding with other apps that also store Data Protection keys in the same database (shared / multi-tenant DBs), override the table name and/or schema:

```csharp
builder.Services.AddPortaDataProtectionWithEntityFrameworkStore(
    opts => opts.UseNpgsql(builder.Configuration.GetConnectionString("dataprotection-db")),
    dp => dp.ProtectKeysWithCertificate(cert),
    tableName: "PortaDataProtectionKeys",
    schema: "porta");
```

The `protectKeys` argument is required. Pass any `ProtectKeysWith…` extension that fits your environment: `ProtectKeysWithCertificate`, `ProtectKeysWithAzureKeyVault` (`Azure.Extensions.AspNetCore.DataProtection.Keys`), `ProtectKeysWithAwsKms` (`AspNetCore.DataProtection.Aws.Kms`), `ProtectKeysWithDpapi` / `ProtectKeysWithDpapiNG` (Windows-only).

**Option B - Redis / Azure Blob / file system / KMS.** Use the open hook and call the standard ASP.NET extension methods for your persistence backend and your key encryptor:

```csharp
var redis = ConnectionMultiplexer.Connect(builder.Configuration["Redis:ConnectionString"]!);
builder.Services.AddPortaDataProtectionPersistence(
    persist: dp => dp.PersistKeysToStackExchangeRedis(redis, "DataProtection-Keys"),
    protectKeys: dp => dp.ProtectKeysWithAzureKeyVault(
        new Uri(builder.Configuration["KeyVault:KeyId"]!),
        new DefaultAzureCredential()));

builder.Services.AddPortaAuthentication(builder.Configuration);
```

Other backends work the same way (`PersistKeysToAzureBlobStorage`, `PersistKeysToFileSystem(new DirectoryInfo("/mnt/keys"))`, etc.).

If no `AddPortaDataProtection*` helper is called, the library logs a warning at startup (event id `14501`). If persistence is configured but no `protectKeys` action is supplied (and no acknowledgement is registered), `AddPortaAuthentication` throws on startup in non-Development environments (event id `14503`); in Development it warns instead (event id `14502`).

#### Dev / single-box exception

For local development, or a single-box production deployment that relies on full-disk encryption and strict file-system permissions, you can opt out of key encryption explicitly:

```csharp
builder.Services.AddPortaDataProtectionPersistence(
    persist: dp => dp.PersistKeysToFileSystem(new DirectoryInfo("./.dp-keys")),
    protectKeys: null);

builder.Services.AcknowledgeUnencryptedDataProtectionKeys(
    reason: "local dev - keys live under ./.dp-keys, never leaves the box");

builder.Services.AddPortaAuthentication(builder.Configuration);
```

The `reason` argument is required so the choice is visible in code review. The acknowledgement only suppresses the startup throw - it does not disable persistence or change any runtime behavior. Do not ship it to a multi-instance deployment: a single read of the key store at that point is enough to decrypt every active session.

### 3. `DataProtection.ApplicationName` - identical on every replica

The `SessionAuthentication:DataProtection:ApplicationName` setting is the Data Protection application discriminator. Replicas sharing key storage but disagreeing on the application name can't read each other's keys. Set it explicitly:

```json
{
  "SessionAuthentication": {
    "DataProtection": {
      "ApplicationName": "my-porta"
    }
  }
}
```

When left empty (the default), `ApplicationName` is derived at startup from the host's entry-assembly name plus `/Porta` (e.g. `MyApp.Api/Porta`), so two different apps don't accidentally share a key ring. Set it explicitly to pin a stable discriminator across deployments - or to *deliberately* share one key ring between apps that should decrypt each other's tickets. Two unrelated BFFs that you want isolated must not be given the same explicit `ApplicationName` against the same key store.

## Why sticky sessions are not required

The OIDC sign-in flow goes:

1. Browser hits replica A → A redirects to the IdP and sets a `.AspNetCore.Correlation.*` cookie (encrypted with Data Protection).
2. Browser → IdP → browser → callback URL.
3. Callback lands on replica B (load balancer round-robin).
4. Replica B reads the correlation cookie *from the browser*, decrypts it (it can - DP keys are shared), validates the nonce, completes sign-in.

That works as long as steps 1 and 4 use the same DP key ring. With shared persistence, they do. **No sticky sessions required.**

The same logic applies to the auth cookie: it carries an opaque ticket id, the ticket itself is in Redis, both are encrypted/decrypted with the shared key ring.

## Why sticky sessions can still help (performance, not correctness)

Sticky sessions are not necessary, but they can shave latency:

- The cookie auth handler reads the ticket from Redis on every authenticated request. Sticky sessions don't change that - `ITicketStore` is hit either way.
- The OIDC discovery cache (`IDiscoveryService`) is per-instance read-through. Sticky sessions keep one replica's cache hot for a given user; spreading evenly means each replica eventually fetches the metadata once. The freshness contract is identical; only the warm-up cost differs and it's tiny.
- Refresh-token coordination (next section) is per-instance. Sticky sessions reduce cross-replica refresh races.

If your load balancer offers cheap session affinity (cookie-based, round-robin within affinity), turn it on for warm-cache wins. Don't *require* it.

## Refresh-token race across replicas

`IRefreshLock` coordinates concurrent token refreshes for the same user. In a multi-replica deployment two replicas can independently decide to refresh the same user's token at the same moment. What happens depends on your IdP:

- **IdPs that allow refresh-token reuse during rotation** (most): both refreshes succeed, the second one wins, the first replica's stale token is discarded on its next request. No user-visible effect.
- **IdPs that enforce strict one-time-use rotation** (some, e.g. some hardened OAuth 2.1 deployments): the loser's rotated-out refresh token is rejected with `invalid_grant`. The library **fails closed** rather than serving the stale access token: it invalidates the derived API tokens, signs the user out, logs a warning, and the current request proceeds unauthenticated. The user must re-authenticate. (Serving the stale token would let a session the IdP has already invalidated keep working, so this is deliberate - see [`AccessTokenRefreshService`](../src/Auth/Tokens/AccessTokenRefreshService.cs).) This is why `IRefreshLock` coordination matters under strict rotation: the goal is to avoid the race producing an `invalid_grant` at all.

### Auto-pick - the default does the right thing

`AddPortaAuthentication` picks an `IRefreshLock` implementation at first resolve, based on the effective registrations in the built container (registration order relative to `AddPortaAuthentication` doesn't matter):

| Effective registration | Auto-picked `IRefreshLock` | When this is right |
|---|---|---|
| Real `IDistributedCache` (Redis/Valkey) | `DistributedCacheRefreshLock` | Multi-replica deployment. |
| No `IDistributedCache` | `RefreshLockRegistry` (in-process) | Single-instance dev/test. |
| Consumer-provided `IRefreshLock` | The consumer's | You know what you're doing. |

`DistributedCacheRefreshLock` uses the same `IDistributedCache` you registered for tickets and sessions - no extra dependency, no extra connection. It implements coordination via a get-then-set with a per-acquire fencing token and a best-effort compare-and-delete release. `IDistributedCache` exposes neither an atomic SET-NX nor an atomic check-and-delete, so the lock is best-effort under contention - and the release likewise narrows, but does not fully close, the window in which a delayed disposer could evict a newer holder's lock; for the refresh-coordination use case that narrows the race window to a small fraction of a refresh round-trip, which is enough to eliminate the strict-rotation `invalid_grant` symptom in practice. Consumers who need a true mutex (e.g. RedLock, a SQL row lock) can register their own `IRefreshLock` and the auto-pick steps aside.

### Single-box production with a remote cache

A single-replica deployment that uses a remote `IDistributedCache` (because some other component needs it) does not need cross-replica refresh coordination - but it doesn't have to do anything special. With a distributed cache registered, the auto-pick installs `DistributedCacheRefreshLock`, which is correct (and cheap) on a single replica too. Leave it alone.

The startup check only refuses to boot in non-Development when the **in-process** `RefreshLockRegistry` is registered alongside a distributed cache, on the assumption that the combination is unintentional on what looks like an HA deployment. If you ever hit that throw and the in-process lock is genuinely what you want, acknowledge it:

```csharp
builder.Services.AcknowledgeInProcessRefreshLock(
    reason: "single VM; remote cache only used by other components");

builder.Services.AddPortaAuthentication(builder.Configuration);
```

The `reason` argument is required so the choice is reviewable in code review. As with `AcknowledgeUnencryptedDataProtectionKeys`, the acknowledgement only suppresses the startup throw - it does not change runtime behavior. Do not use it on a real multi-replica deployment.

### Replacing the lock with your own implementation

The `IRefreshLock` contract is a single method, `Task<RefreshLockHandle> AcquireAsync(string lockKey, TimeSpan timeout, CancellationToken cancellationToken = default)`. The returned `RefreshLockHandle` is `IAsyncDisposable` (dispose it to release) and exposes an `Acquired` flag so callers can tell a real acquisition from a best-effort timeout. Register your implementation before or after `AddPortaAuthentication` - a consumer-provided `IRefreshLock` always wins over the auto-pick:

```csharp
builder.Services.AddSingleton<IRefreshLock, MyRedLockRefreshLock>();

builder.Services.AddPortaAuthentication(builder.Configuration);
```

## Sample HA configuration

```csharp
var builder = WebApplication.CreateBuilder(args);

// 1. Distributed cache (order relative to AddPortaAuthentication doesn't matter).
builder.Services.AddStackExchangeRedisCache(opts =>
{
    opts.Configuration = builder.Configuration["Redis:ConnectionString"];
});

// 2. Data Protection persistence + key encryption at rest - pick one persistence backend
//    and one key encryptor. The protectKeys argument is required.
using var dpCert = new X509Certificate2(
    builder.Configuration["DataProtection:CertPath"]!,
    builder.Configuration["DataProtection:CertPassword"]);

builder.Services.AddPortaDataProtectionWithEntityFrameworkStore(
    opts => opts.UseNpgsql(builder.Configuration.GetConnectionString("dataprotection-db")),
    dp => dp.ProtectKeysWithCertificate(dpCert));

// 3. Core BFF + auth.
builder.Services.AddPortaCore(opts =>
{
    opts.TrustedHosts = ["https://api.internal.example.com"];
});

builder.Services.AddPortaAuthentication(builder.Configuration);

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.Run();
```

```jsonc
// appsettings.Production.json
{
  "ConnectionStrings": {
    "dataprotection-db": "Host=...;Database=keys;Username=...;Password=..."
  },
  "Redis": {
    "ConnectionString": "redis-primary:6379,password=...,ssl=true"
  },
  "SessionAuthentication": {
    "Authority": "https://auth.example.com",
    "ClientId": "my-porta",
    "ClientSecret": "...",
    "Cookie": {
      "SameSite": "Lax",
      "SecurePolicy": "Always"
    },
    "DataProtection": {
      "ApplicationName": "my-porta",
      "KeyLifetimeDays": 90
    },
    "SessionKeys": {
      "Prefix": "my-porta"
    }
  }
}
```

`SessionKeys.Prefix` should be unique per BFF instance group when multiple BFFs share Redis (otherwise their session keys collide). Inside a single replica set, all replicas use the same prefix.

`Cookie.SameSite` should be `Lax` for the OIDC redirect-back flow to set cookies. Browsers only send `Strict` cookies on same-site navigations, so with `Strict` (the library default) a callback redirect arriving from a cross-site IdP never carries the correlation cookie and sign-in fails; a same-site IdP works fine with `Strict`, which is why it remains the default.

## Failure modes - what each missing piece looks like

| Symptom | Likely cause |
|---|---|
| Sign-in fails with `Correlation failed` after IdP callback | Replica B can't decrypt the correlation cookie set by replica A → DP keys not shared. |
| Auth cookie present but user appears logged out on every other request | Ticket store is per-instance → no shared `IDistributedCache`. |
| `Failed to decrypt auth ticket ... (data protection key rotation?)` warnings | DP keys rotated while old keys not in shared store, or replicas have divergent key rings. |
| Sporadic `invalid_grant` on token refresh | Strict-rotation IdP + in-process refresh lock on a multi-replica deployment. The default auto-pick installs `DistributedCacheRefreshLock` when a distributed cache is registered; if you're seeing this anyway, check whether something is registering `RefreshLockRegistry` explicitly. See [Refresh-token race](#refresh-token-race-across-replicas). |
| `Skipping IdP-side revocation ... no encrypted refresh token on metadata` on logout | Refresh-token rotation didn't sync to session metadata, usually because the original sign-in landed on a replica with a different key ring. Resolve DP persistence first. |
| `AddPortaAuthentication` throws `InvalidOperationException` referencing event id `14503` | DP persistence is configured but no `protectKeys` action and no `AcknowledgeUnencryptedDataProtectionKeys` call. Pass a `ProtectKeysWith…` callback or, for dev / single-box, register the acknowledgement. |

Startup diagnostics emitted by the library:

- `Porta: no real IDistributedCache is registered; using the in-memory fallback` - warning, event id `14500`. Fine for single-instance dev; HA-fatal in production.
- `Porta: Data Protection key persistence is not configured` - warning, event id `14501`. HA-fatal in production.
- `Porta: Data Protection keys are persisted without encryption at rest` (Development only) - warning, event id `14502`. Acceptable for dev loops; in non-Development it becomes a startup throw instead.
- `Porta: Data Protection keys are persisted without encryption at rest and no explicit acknowledgement` - critical log + thrown `InvalidOperationException`, event id `14503`. Refuses to start.
- `Porta: a distributed cache is registered but the in-process RefreshLockRegistry was registered explicitly` (Development only) - warning, event id `14504`. In non-Development it becomes a startup throw instead.
- `Porta: a distributed cache is registered but the in-process RefreshLockRegistry was registered explicitly and no acknowledgement was provided` - critical log + thrown `InvalidOperationException`, event id `14505`. Refuses to start.
- `Porta: a Data Protection protectKeys action was supplied but registered no IXmlEncryptor (e.g. an empty lambda), so keys are still persisted in plaintext` (Development only) - warning, event id `14506`. The attestation is hollow; in non-Development it becomes a startup throw instead.
- `Porta: a Data Protection protectKeys action was supplied but registered no IXmlEncryptor` - critical log + thrown `InvalidOperationException`, event id `14507`. Refuses to start (a hollow `protectKeys` attestation outside Development).

If you see `14500` or `14501` in production logs, your deployment is not HA-safe. If you see `14502`, `14504`, or `14506`, you have a configuration that will become a startup failure as soon as the environment isn't Development.

## Rolling deploys and key rotation

`KeyLifetimeDays` (default 90) controls when DP generates a new key. Rotation is automatic and old keys remain in the store until they expire - a rolling deploy where some replicas have v1 and others have v2 of the keyring is fine as long as both versions are still in shared storage. Don't truncate the `DataProtectionKeys` table or delete the Redis hash; you'll invalidate every active session.

When you rotate `DataProtection.ApplicationName`, you invalidate every active session (which is the point - that's the documented reset switch).

## Health Probes

`AddPortaHealthChecks()` registers readiness checks for exactly the pieces this page tells you
to share: the distributed cache (sessions/locks/revocation), the Data Protection key ring and
key store, plus network-level IdP discovery reachability. Wire them into your readiness probe
only - a dependency outage should pull replicas from rotation, not restart them. When the check
detects the in-memory `MemoryDistributedCache` in a deployment that bothers with probes, it
logs a warning: that combination means sessions are not shared across replicas. See
[Health Checks](health-checks.md) for registration, Kubernetes wiring, and the
Degraded-vs-Unhealthy semantics.

## Related

- [Health Checks](health-checks.md) - readiness probes for the shared stores and the IdP.
- [Configuration](configuration.md) - full options reference.
- [Authentication](authentication.md) - session, reference token, JWT providers.
- [OIDC Endpoints](oidc.md) - login/logout/back-channel logout middleware.
